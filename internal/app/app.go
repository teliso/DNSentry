package app

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	DNSListen             string           `json:"dns_listen"`
	DNSListens            []string         `json:"dns_listens,omitempty"`
	HTTPListen            string           `json:"http_listen"`
	Upstreams             []string         `json:"upstreams"`
	FallbackUpstreams     []string         `json:"fallback_upstreams"`
	UpstreamMode          string           `json:"upstream_mode"`
	LocalRecords          []LocalRecord    `json:"local_records,omitempty"`
	BootstrapDNS          []string         `json:"bootstrap_dns"`
	UpstreamTimeout       int              `json:"upstream_timeout_seconds"`
	BlockingMode          string           `json:"blocking_mode"`
	BlockingIPv4          string           `json:"blocking_ipv4"`
	BlockingIPv6          string           `json:"blocking_ipv6"`
	EnableDNSSEC          bool             `json:"enable_dnssec"`
	DNSSECValidate        bool             `json:"dnssec_validate"`
	DNSSECTrustAnchors    []string         `json:"dnssec_trust_anchors,omitempty"`
	DNSSECTrustAnchorFile string           `json:"dnssec_trust_anchor_file"`
	DNSSECAutoUpdate      bool             `json:"dnssec_auto_update"`
	BlockedResponseTTL    uint32           `json:"blocked_response_ttl"`
	RulesFile             string           `json:"rules_file"`
	CacheEnabled          bool             `json:"cache_enabled"`
	CacheSize             int              `json:"cache_size"`
	QueryLogSize          int              `json:"query_log_size"`
	QueryLogEnabled       bool             `json:"query_log_enabled"`
	QueryLogFile          string           `json:"query_log_file"`
	QueryLogRetentionDays int              `json:"query_log_retention_days"`
	CacheTTLMin           uint32           `json:"cache_ttl_min"`
	CacheTTLMax           uint32           `json:"cache_ttl_max"`
	OptimisticCache       bool             `json:"cache_optimistic"`
	OptimisticAnswerTTL   uint32           `json:"cache_optimistic_answer_ttl"`
	OptimisticMaxAge      uint32           `json:"cache_optimistic_max_age"`
	RuleSources           []RuleSource     `json:"rule_sources,omitempty"`
	Access                DNSAccessConfig  `json:"access" yaml:"access"`
	Encryption            EncryptionConfig `json:"encryption" yaml:"encryption"`
}

const shutdownTimeout = 10 * time.Second

func Run(webFiles embed.FS) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	apiToken := os.Getenv("VIGORDNS_API_TOKEN")
	if !isLoopbackHTTPListen(config.HTTPListen) {
		if os.Getenv("VIGORDNS_ALLOW_PUBLIC_WEB") != "1" {
			log.Fatalf("refusing non-loopback Web listen address %q; set VIGORDNS_ALLOW_PUBLIC_WEB=1 to allow public Web access", config.HTTPListen)
		}
		if apiToken == "" {
			log.Fatalf("refusing public Web access without VIGORDNS_API_TOKEN")
		}
	}
	if err := os.MkdirAll(filepath.Dir(config.RulesFile), 0755); err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(config.RulesFile); os.IsNotExist(err) {
		if err := os.WriteFile(config.RulesFile, nil, 0644); err != nil {
			log.Fatal(err)
		}
	}

	rules := NewRuleStore(config.RulesFile)
	if err := rules.Reload(); err != nil {
		log.Fatal(err)
	}
	logs, err := NewQueryLoggerWithPersistence(config.QueryLogSize, QueryLogPersistenceConfig{
		Enabled:       config.QueryLogEnabled,
		File:          config.QueryLogFile,
		RetentionDays: config.QueryLogRetentionDays,
	})
	if err != nil {
		log.Fatalf("initialize query logger: %v", err)
	}
	defer func() {
		if err := logs.Close(); err != nil {
			log.Printf("close query logger: %v", err)
		}
	}()
	server := &DNSServer{
		config:        config,
		rules:         rules,
		cache:         NewDNSCache(config.CacheSize, config.CacheEnabled),
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
			log.Fatalf("initialize DNSSEC validator: %v", err)
		}
	}

	dnscryptService, err := NewDNSCryptService(server, config.Encryption.DNSCrypt)
	if err != nil {
		log.Fatalf("initialize DNSCrypt service: %v", err)
	}
	if generatedConfig := dnscryptService.Config(); !dnsCryptConfigEqual(generatedConfig, config.Encryption.DNSCrypt) {
		config.Encryption.DNSCrypt = generatedConfig
		if err := saveConfig(config); err != nil {
			_ = dnscryptService.Close()
			log.Fatalf("persist DNSCrypt configuration: %v", err)
		}
	}

	secureConfig := config.Encryption
	// DNSCrypt is owned and started explicitly by main. Keep it out of the
	// legacy encrypted listener service so it is not constructed twice.
	secureConfig.DNSCrypt = DNSCryptConfig{}
	if !hasSecureListeners(secureConfig) {
		secureConfig.Enabled = false
	}
	secureService, err := NewSecureDNSService(server, secureConfig)
	if err != nil {
		_ = dnscryptService.Close()
		log.Fatalf("initialize encrypted DNS service: %v", err)
	}
	if err := secureService.Bind(); err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		log.Fatalf("bind encrypted DNS service: %v", err)
	}
	if err := dnscryptService.Bind(); err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		log.Fatalf("bind DNSCrypt service: %v", err)
	}

	// Bind every listener before starting any service so a port conflict fails cleanly.
	dnsService, err := NewDNSService(server, *config)
	if err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		log.Fatalf("initialize DNS service: %v", err)
	}
	if err := dnsService.Bind(); err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		log.Fatalf("bind DNS service: %v", err)
	}

	updater := NewRuleUpdater(rules, config.RuleSources)
	api := newAPI(rules, server.cache, server.logs, server, updater, dnscryptService)
	api.apiToken = apiToken
	api.ctx = ctx
	static, err := fs.Sub(webFiles, "web/dist")
	if err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		_ = dnsService.Close()
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", api.handle)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !dnsService.Ready() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.Handle("/", http.FileServer(http.FS(static)))
	httpListener, err := net.Listen("tcp", config.HTTPListen)
	if err != nil {
		_ = secureService.Close()
		_ = dnscryptService.Close()
		_ = dnsService.Close()
		log.Fatalf("Web UI cannot listen on %s: %v", config.HTTPListen, err)
	}
	for _, address := range dnsService.Addresses() {
		log.Printf("DNS UDP and TCP listening on %s", address)
	}

	httpServer := &http.Server{
		Handler:           withCORS(withJSONBodyLimit(mux)),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
	log.Printf("Web UI listening on http://%s", httpListener.Addr().String())
	httpServeDone := make(chan error, 1)
	if err := dnscryptService.Start(ctx); err != nil {
		_ = httpListener.Close()
		_ = secureService.Close()
		_ = dnscryptService.Close()
		_ = dnsService.Close()
		log.Fatalf("start DNSCrypt service: %v", err)
	}
	if err := secureService.Start(ctx); err != nil {
		_ = httpListener.Close()
		_ = secureService.Close()
		_ = dnscryptService.Close()
		_ = dnsService.Close()
		log.Fatalf("start encrypted DNS service: %v", err)
	}
	if err := dnsService.Start(ctx); err != nil {
		_ = httpListener.Close()
		_ = secureService.Close()
		_ = dnscryptService.Close()
		_ = dnsService.Close()
		log.Fatalf("start DNS service: %v", err)
	}
	updaterDone := make(chan struct{})
	go func() {
		defer close(updaterDone)
		updater.Run(ctx)
	}()
	dnssecAnchorDone := make(chan struct{})
	go server.watchDNSSECTrustAnchorFile(ctx, dnssecAnchorDone)
	go func() {
		httpServeDone <- httpServer.Serve(httpListener)
	}()

	select {
	case err := <-httpServeDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Web UI stopped: %v", err)
		}
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	}
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownResults := make(chan struct {
		name string
		err  error
	}, 5)
	go func() {
		shutdownResults <- struct {
			name string
			err  error
		}{"HTTP", httpServer.Shutdown(shutdownCtx)}
	}()
	go func() {
		shutdownResults <- struct {
			name string
			err  error
		}{"DNS", dnsService.Shutdown(shutdownCtx)}
	}()

	go func() {
		shutdownResults <- struct {
			name string
			err  error
		}{"Secure DNS", secureService.Shutdown(shutdownCtx)}
	}()
	go func() {
		shutdownResults <- struct {
			name string
			err  error
		}{"DNSCrypt", dnscryptService.Shutdown(shutdownCtx)}
	}()
	go func() {
		shutdownResults <- struct {
			name string
			err  error
		}{"DoH transports", server.Close()}
	}()

	for remaining := 5; remaining > 0; {
		select {
		case result := <-shutdownResults:
			remaining--
			if result.err != nil {
				log.Printf("%s graceful shutdown: %v", result.name, result.err)
			}
		case <-shutdownCtx.Done():
			log.Printf("graceful shutdown timed out; forcing listeners closed")
			_ = httpServer.Close()
			_ = dnsService.Close()
			_ = secureService.Close()
			_ = dnscryptService.Close()
			remaining = 0
		}
	}
	select {
	case <-updaterDone:
	case <-shutdownCtx.Done():
		log.Printf("rule updater did not stop before shutdown deadline")
	}
	select {
	case <-dnssecAnchorDone:
	case <-shutdownCtx.Done():
		log.Printf("DNSSEC trust anchor watcher did not stop before shutdown deadline")
	}
}
