package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/buildinfo"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

const shutdownTimeout = 10 * time.Second

// listenerService is implemented by every network front end (plain DNS, the
// encrypted DNS listeners and DNSCrypt). Bind reserves the sockets, Start begins
// serving, Shutdown drains gracefully and Close releases everything at once.
type listenerService interface {
	Bind() error
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Close() error
}

// SetConfigPath selects the YAML configuration file. Call it before Run or
// CheckConfig.
func SetConfigPath(path string) {
	if path != "" {
		configFile = path
	}
}

// CheckConfig validates the configuration file and the environment it needs
// without starting any listener.
func CheckConfig() error {
	config, err := readConfig()
	if err != nil {
		return err
	}
	return checkWebExposure(config, os.Getenv("DNSENTRY_API_TOKEN"))
}

// Run starts DNSentry and blocks until it receives SIGINT/SIGTERM or the Web
// console stops. static is the built console, rooted at its index.html.
func Run(static fs.FS) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("starting DNSentry", "version", buildinfo.String(), "config", configPath())
	return run(ctx, stop, static)
}

func checkWebExposure(config *Config, apiToken string) error {
	if isLoopbackHTTPListen(config.HTTPListen) {
		return nil
	}
	if os.Getenv("DNSENTRY_ALLOW_PUBLIC_WEB") != "1" {
		return fmt.Errorf("refusing non-loopback Web listen address %q; set DNSENTRY_ALLOW_PUBLIC_WEB=1 to allow public Web access", config.HTTPListen)
	}
	if apiToken == "" {
		return errors.New("refusing public Web access without DNSENTRY_API_TOKEN")
	}
	return nil
}

// ruleCacheDir is where downloaded remote rule lists are kept, next to the
// local rules file.
func ruleCacheDir(rulesFile string) string {
	return filepath.Join(filepath.Dir(rulesFile), "remote")
}

const defaultRulesFile = `# DNSentry local filter rules. One rule per line:
#   example.com              block example.com and its subdomains
#   ||ads.example.com^       same, AdGuard syntax
#   @@||good.example.com^    allow (overrides blocks)
#   0.0.0.0 a.example b.example
# Lines starting with # or ! are comments.
`

func ensureRulesFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.WriteFile(path, []byte(defaultRulesFile), 0644)
	}
	return nil
}

func run(ctx context.Context, stop context.CancelFunc, static fs.FS) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}
	apiToken := os.Getenv("DNSENTRY_API_TOKEN")
	if err := checkWebExposure(config, apiToken); err != nil {
		return err
	}
	if err := ensureRulesFile(config.RulesFile); err != nil {
		return err
	}

	ruleStore := rules.NewStore(config.RulesFile)
	if err := ruleStore.Reload(); err != nil {
		return err
	}
	logs, err := querylog.NewWithPersistence(config.QueryLogSize, querylog.PersistenceConfig{
		Enabled:       config.QueryLogEnabled,
		File:          config.QueryLogFile,
		RetentionDays: config.QueryLogRetentionDays,
	})
	if err != nil {
		return fmt.Errorf("initialize query logger: %w", err)
	}
	defer func() {
		if err := logs.Close(); err != nil {
			slog.Error("close query logger", "error", err)
		}
	}()

	server := &DNSServer{
		config:        config,
		rules:         ruleStore,
		cache:         cache.New(config.CacheSize, config.CacheEnabled),
		logs:          logs,
		client:        &dns.Client{Net: "udp", Timeout: upstreamTimeout(config.UpstreamTimeout)},
		pool:          NewUpstreamPool(config.Upstreams),
		fallbackPool:  NewUpstreamPool(config.FallbackUpstreams),
		dnssecCacheOK: make(map[string]struct{}),
	}
	server.configureAccess(config.Access)
	server.setLocalRecords(config.LocalRecords)
	if config.DNSSECValidate {
		if err := server.rebuildDNSSECValidator(*config); err != nil {
			return fmt.Errorf("initialize DNSSEC validator: %w", err)
		}
	}

	services, dnsService, err := buildListenerServices(server, config)
	if err != nil {
		return err
	}
	// Bind every listener before starting any service so a port conflict fails cleanly.
	if err := services.bind(); err != nil {
		services.closeAll()
		return err
	}

	updater := rules.NewUpdater(ruleStore, ruleCacheDir(config.RulesFile), config.RuleSources)
	api := newAPI(ctx, apiToken, server, updater, services.dnscrypt)
	httpServer := newHTTPServer(api, static, dnsService.Ready)
	httpListener, err := net.Listen("tcp", config.HTTPListen)
	if err != nil {
		services.closeAll()
		return fmt.Errorf("web UI cannot listen on %s: %w", config.HTTPListen, err)
	}
	for _, address := range dnsService.Addresses() {
		slog.Info("DNS listening", "address", address, "protocols", "udp,tcp")
	}
	slog.Info("web console listening", "url", "http://"+httpListener.Addr().String())

	if err := services.start(ctx); err != nil {
		_ = httpListener.Close()
		services.closeAll()
		return err
	}
	updaterDone := make(chan struct{})
	go func() {
		defer close(updaterDone)
		updater.Run(ctx)
	}()
	dnssecAnchorDone := make(chan struct{})
	go server.watchDNSSECTrustAnchorFile(ctx, dnssecAnchorDone)
	httpServeDone := make(chan error, 1)
	go func() { httpServeDone <- httpServer.Serve(httpListener) }()

	select {
	case err := <-httpServeDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("web console stopped", "error", err)
		}
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if !shutdownAll(shutdownCtx, httpServer, services, server) {
		slog.Warn("graceful shutdown timed out; forcing listeners closed")
		_ = httpServer.Close()
		services.closeAll()
	}
	waitFor(shutdownCtx, updaterDone, "rule updater")
	waitFor(shutdownCtx, dnssecAnchorDone, "DNSSEC trust anchor watcher")
	return nil
}

// listenerServices owns the DNS front ends in start order.
type listenerServices struct {
	dnscrypt *DNSCryptService
	secure   *SecureDNSService
	dns      *DNSService
}

func (s listenerServices) ordered() []struct {
	name    string
	service listenerService
} {
	return []struct {
		name    string
		service listenerService
	}{{"DNSCrypt", s.dnscrypt}, {"Secure DNS", s.secure}, {"DNS", s.dns}}
}

func buildListenerServices(server *DNSServer, config *Config) (listenerServices, *DNSService, error) {
	var services listenerServices
	var err error
	if services.dnscrypt, err = NewDNSCryptService(server, config.Encryption.DNSCrypt); err != nil {
		return services, nil, fmt.Errorf("initialize DNSCrypt service: %w", err)
	}
	// The service may generate keys on first start; persist them so the
	// provider stamp stays stable across restarts.
	if generated := services.dnscrypt.Config(); !dnsCryptConfigEqual(generated, config.Encryption.DNSCrypt) {
		config.Encryption.DNSCrypt = generated
		if err := saveConfig(config); err != nil {
			_ = services.dnscrypt.Close()
			return services, nil, fmt.Errorf("persist DNSCrypt configuration: %w", err)
		}
	}

	secureConfig := config.Encryption
	// DNSCrypt is owned and started explicitly here. Keep it out of the
	// encrypted listener service so it is not constructed twice.
	secureConfig.DNSCrypt = DNSCryptConfig{}
	if !hasSecureListeners(secureConfig) {
		secureConfig.Enabled = false
	}
	if services.secure, err = NewSecureDNSService(server, secureConfig); err != nil {
		_ = services.dnscrypt.Close()
		return services, nil, fmt.Errorf("initialize encrypted DNS service: %w", err)
	}
	if services.dns, err = NewDNSService(server, *config); err != nil {
		services.closeAll()
		return services, nil, fmt.Errorf("initialize DNS service: %w", err)
	}
	return services, services.dns, nil
}

func (s listenerServices) bind() error {
	for _, entry := range s.ordered() {
		if err := entry.service.Bind(); err != nil {
			return fmt.Errorf("bind %s service: %w", entry.name, err)
		}
	}
	return nil
}

func (s listenerServices) start(ctx context.Context) error {
	for _, entry := range s.ordered() {
		if err := entry.service.Start(ctx); err != nil {
			return fmt.Errorf("start %s service: %w", entry.name, err)
		}
	}
	return nil
}

func (s listenerServices) closeAll() {
	for _, entry := range s.ordered() {
		_ = entry.service.Close()
	}
}

// shutdownAll drains the Web server, every DNS service and the DoH transports
// in parallel. It reports false if ctx expired first.
func shutdownAll(ctx context.Context, httpServer *http.Server, services listenerServices, server *DNSServer) bool {
	type job struct {
		name string
		run  func() error
	}
	jobs := []job{
		{"HTTP", func() error { return httpServer.Shutdown(ctx) }},
		{"DoH transports", server.Close},
	}
	for _, entry := range services.ordered() {
		jobs = append(jobs, job{entry.name, func() error { return entry.service.Shutdown(ctx) }})
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := j.run(); err != nil {
				slog.Warn("graceful shutdown failed", "component", j.name, "error", err)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

func waitFor(ctx context.Context, done <-chan struct{}, name string) {
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("component did not stop before shutdown deadline", "component", name)
	}
}
