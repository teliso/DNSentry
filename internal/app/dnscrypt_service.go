package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
)

// DNSCryptConfig controls the DNSCrypt v2 resolver listener.  The private key
// and resolver secret are hex-encoded and are generated on first enable when
// omitted.
type DNSCryptConfig struct {
	Enabled             bool     `json:"enabled" yaml:"enabled"`
	Listen              string   `json:"-" yaml:"listen,omitempty"` // legacy single address: read from old files, never written
	Listens             []string `json:"listens,omitempty" yaml:"listens,omitempty"`
	ProviderName        string   `json:"provider_name" yaml:"provider_name"`
	PrivateKey          string   `json:"private_key" yaml:"private_key"`
	ResolverSecret      string   `json:"resolver_secret" yaml:"resolver_secret"`
	CertificateTTLHours int      `json:"certificate_ttl_hours" yaml:"certificate_ttl_hours"`
}

const defaultDNSCryptCertificateTTLHours = 24

func normalizeDNSCryptListeners(config *DNSCryptConfig) error {
	if config == nil {
		return errors.New("dnscrypt config is nil")
	}
	addresses, err := normalizeListenAddresses("DNSCrypt listen", config.Listen, config.Listens)
	if err != nil {
		return err
	}
	config.Listens = addresses
	config.Listen = "" // input-only: folded into Listens
	return nil
}

func validateDNSCryptConfig(config DNSCryptConfig) error {
	if !config.Enabled {
		return nil
	}
	addresses, err := normalizeListenAddresses("DNSCrypt listen", config.Listen, config.Listens)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("dnscrypt listen address is required when DNSCrypt is enabled")
	}
	if strings.TrimSpace(config.ProviderName) == "" {
		return errors.New("dnscrypt provider_name is required when DNSCrypt is enabled")
	}
	providerName := strings.TrimPrefix(strings.TrimSpace(config.ProviderName), dnscrypt.DNSCryptV2Prefix)
	if !validHost(providerName) {
		return fmt.Errorf("invalid DNSCrypt provider_name %q", config.ProviderName)
	}
	if config.CertificateTTLHours < 0 {
		return errors.New("dnscrypt certificate_ttl_hours must not be negative")
	}
	if config.CertificateTTLHours > 87600 {
		return errors.New("dnscrypt certificate_ttl_hours is too large")
	}
	if key := strings.TrimSpace(config.PrivateKey); key != "" {
		decoded, err := dnscrypt.HexDecodeKey(key)
		if err != nil || (len(decoded) != ed25519.PrivateKeySize && len(decoded) != ed25519.SeedSize) {
			return errors.New("dnscrypt private_key must be a 32-byte seed or 64-byte private key in hexadecimal")
		}
	}
	if secret := strings.TrimSpace(config.ResolverSecret); secret != "" {
		decoded, err := dnscrypt.HexDecodeKey(secret)
		if err != nil || len(decoded) != dnscrypt.KeySize {
			return errors.New("dnscrypt resolver_secret must be a 32-byte hexadecimal key")
		}
	}
	return nil
}

// prepareDNSCryptConfig fills in all persistent values required by a resolver.
// It returns true when the caller should persist the updated configuration.
func prepareDNSCryptConfig(config *DNSCryptConfig) (bool, error) {
	if config == nil || !config.Enabled {
		return false, nil
	}
	if err := normalizeDNSCryptListeners(config); err != nil {
		return false, err
	}
	if err := validateDNSCryptConfig(*config); err != nil {
		return false, err
	}
	before := *config
	privateKey, err := dnsCryptPrivateKey(config.PrivateKey)
	if err != nil {
		return false, err
	}
	ttlHours := config.CertificateTTLHours
	if ttlHours == 0 {
		ttlHours = defaultDNSCryptCertificateTTLHours
	}
	resolverConfig, err := dnscrypt.GenerateResolverConfig(
		strings.TrimSpace(config.ProviderName), privateKey, time.Duration(ttlHours)*time.Hour,
	)
	if err != nil {
		return false, fmt.Errorf("generate DNSCrypt resolver config: %w", err)
	}
	if secret := strings.TrimSpace(config.ResolverSecret); secret != "" {
		secretBytes, decodeErr := dnscrypt.HexDecodeKey(secret)
		if decodeErr != nil {
			return false, fmt.Errorf("decode DNSCrypt resolver secret: %w", decodeErr)
		}
		var secretKey, publicKey [dnscrypt.KeySize]byte
		copy(secretKey[:], secretBytes)
		curve25519.ScalarBaseMult(&publicKey, &secretKey)
		resolverConfig.ResolverSk = dnscrypt.HexEncodeKey(secretKey[:])
		resolverConfig.ResolverPk = dnscrypt.HexEncodeKey(publicKey[:])
	}
	config.ProviderName = resolverConfig.ProviderName
	config.PrivateKey = resolverConfig.PrivateKey
	config.ResolverSecret = resolverConfig.ResolverSk
	config.CertificateTTLHours = ttlHours
	return !dnsCryptConfigEqual(*config, before), nil
}

func dnsCryptPrivateKey(value string) (ed25519.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	decoded, err := dnscrypt.HexDecodeKey(value)
	if err != nil {
		return nil, fmt.Errorf("decode DNSCrypt private key: %w", err)
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("DNSCrypt private key must contain 32 or 64 bytes")
	}
	return ed25519.PrivateKey(decoded), nil
}

type dnscryptServiceState uint8

const (
	dnscryptServiceNew dnscryptServiceState = iota
	dnscryptServiceBound
	dnscryptServiceRunning
	dnscryptServiceStopping
	dnscryptServiceClosed
)

// DNSCryptService owns both DNSCrypt v2 transports and delegates decrypted
// queries to DNSServer.ServeDNS.
type DNSCryptService struct {
	server         *DNSServer
	config         DNSCryptConfig
	resolverConfig dnscrypt.ResolverConfig
	certificate    *dnscrypt.Certificate
	servers        []*dnscrypt.Server

	mu          sync.Mutex
	lifecycleMu sync.Mutex
	state       dnscryptServiceState
	cancel      context.CancelFunc
	stopDone    chan struct{}
}

// DNSCryptStatus is intentionally independent of the API package so it can be
// exposed by a future API without coupling this service to HTTP.
type DNSCryptStatus struct {
	Enabled      bool     `json:"enabled"`
	Running      bool     `json:"running"`
	Listens      []string `json:"listens,omitempty"`
	ProviderName string   `json:"provider_name"`
	Stamp        string   `json:"stamp,omitempty"`
}

func NewDNSCryptService(server *DNSServer, config DNSCryptConfig) (*DNSCryptService, error) {
	if server == nil {
		return nil, errors.New("DNSCrypt service requires a DNS server")
	}
	if config.Enabled {
		if err := normalizeDNSCryptListeners(&config); err != nil {
			return nil, err
		}
	}
	if err := validateDNSCryptConfig(config); err != nil {
		return nil, err
	}
	service := &DNSCryptService{server: server, config: config, state: dnscryptServiceNew}
	if !config.Enabled {
		return service, nil
	}
	if _, err := prepareDNSCryptConfig(&service.config); err != nil {
		return nil, err
	}
	resolverConfig, err := dnsCryptResolverConfig(service.config)
	if err != nil {
		return nil, err
	}
	certificate, err := resolverConfig.NewCert()
	if err != nil {
		return nil, fmt.Errorf("generate DNSCrypt certificate: %w", err)
	}
	if err := certificate.Validate(); err != nil {
		return nil, fmt.Errorf("validate DNSCrypt certificate: %w", err)
	}
	privateKey, err := dnsCryptPrivateKey(service.config.PrivateKey)
	if err != nil {
		return nil, err
	}
	if !certificate.VerifySignature(privateKey.Public().(ed25519.PublicKey)) {
		return nil, errors.New("DNSCrypt certificate signature validation failed")
	}
	service.resolverConfig = resolverConfig
	service.certificate = certificate
	return service, nil
}

func dnsCryptResolverConfig(config DNSCryptConfig) (dnscrypt.ResolverConfig, error) {
	privateKey, err := dnsCryptPrivateKey(config.PrivateKey)
	if err != nil {
		return dnscrypt.ResolverConfig{}, err
	}
	resolverConfig, err := dnscrypt.GenerateResolverConfig(
		config.ProviderName, privateKey, time.Duration(config.CertificateTTLHours)*time.Hour,
	)
	if err != nil {
		return dnscrypt.ResolverConfig{}, fmt.Errorf("generate DNSCrypt resolver config: %w", err)
	}
	secretBytes, err := dnscrypt.HexDecodeKey(config.ResolverSecret)
	if err != nil || len(secretBytes) != dnscrypt.KeySize {
		return dnscrypt.ResolverConfig{}, errors.New("DNSCrypt resolver secret is invalid")
	}
	var secretKey, publicKey [dnscrypt.KeySize]byte
	copy(secretKey[:], secretBytes)
	curve25519.ScalarBaseMult(&publicKey, &secretKey)
	resolverConfig.ResolverSk = dnscrypt.HexEncodeKey(secretKey[:])
	resolverConfig.ResolverPk = dnscrypt.HexEncodeKey(publicKey[:])
	return resolverConfig, nil
}

func dnsCryptAddr(value string) (netip.AddrPort, error) {
	value = strings.TrimSpace(value)
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse DNSCrypt listen address: %w", err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse DNSCrypt listen host: %w", err)
	}
	portNumber, err := net.LookupPort("tcp", port)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse DNSCrypt listen port: %w", err)
	}
	return netip.AddrPortFrom(address, uint16(portNumber)), nil
}

func (s *DNSCryptService) Bind() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != dnscryptServiceNew {
		return fmt.Errorf("DNSCrypt service cannot bind in state %d", s.state)
	}
	if !s.config.Enabled {
		s.state = dnscryptServiceBound
		return nil
	}
	addresses, err := normalizeListenAddresses("DNSCrypt listen", s.config.Listen, s.config.Listens)
	if err != nil {
		return err
	}
	handler := dnscrypt.HandlerFunc(s.serveDNSCrypt)
	for _, addressValue := range addresses {
		address, addressErr := dnsCryptAddr(addressValue)
		if addressErr != nil {
			s.rollbackBoundServersLocked()
			return addressErr
		}
		for _, proto := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
			resolver, serverErr := dnscrypt.NewServer(&dnscrypt.ServerConfig{
				Handler:      handler,
				ResolverCert: s.certificate,
				ProviderName: s.config.ProviderName,
				Addr:         address,
				Proto:        proto,
			})
			if serverErr != nil {
				s.rollbackBoundServersLocked()
				return fmt.Errorf("create DNSCrypt %s server: %w", proto, serverErr)
			}
			s.servers = append(s.servers, resolver)
		}
	}
	s.state = dnscryptServiceBound
	return nil
}

func (s *DNSCryptService) rollbackBoundServersLocked() {
	for _, boundResolver := range s.servers {
		_ = boundResolver.Shutdown(context.Background())
	}
	s.servers = nil
}

func (s *DNSCryptService) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.state != dnscryptServiceBound {
		state := s.state
		s.mu.Unlock()
		return fmt.Errorf("DNSCrypt service must be bound before start (state %d)", state)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.state = dnscryptServiceRunning
	s.cancel = cancel
	s.stopDone = make(chan struct{})
	servers := append([]*dnscrypt.Server(nil), s.servers...)
	s.mu.Unlock()

	started := make([]*dnscrypt.Server, 0, len(servers))
	for _, resolver := range servers {
		started = append(started, resolver)
		if err := resolver.Start(runCtx); err != nil {
			cancel()
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, startedResolver := range started {
				_ = startedResolver.Shutdown(cleanupCtx)
			}
			cleanupCancel()
			s.mu.Lock()
			s.state = dnscryptServiceClosed
			if s.stopDone != nil {
				close(s.stopDone)
			}
			s.mu.Unlock()
			return fmt.Errorf("start DNSCrypt server: %w", err)
		}
	}
	go func() {
		<-runCtx.Done()
		_ = s.Shutdown(context.Background())
	}()
	return nil
}

func (s *DNSCryptService) shutdown(ctx context.Context) error {
	s.mu.Lock()
	switch s.state {
	case dnscryptServiceNew, dnscryptServiceClosed:
		s.mu.Unlock()
		return nil
	case dnscryptServiceStopping:
		done := s.stopDone
		s.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case dnscryptServiceBound, dnscryptServiceRunning:
		s.state = dnscryptServiceStopping
		if s.stopDone == nil {
			s.stopDone = make(chan struct{})
		}
		done := s.stopDone
		cancel := s.cancel
		servers := append([]*dnscrypt.Server(nil), s.servers...)
		s.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		var shutdownErr error
		for _, resolver := range servers {
			shutdownErr = errors.Join(shutdownErr, resolver.Shutdown(ctx))
		}
		s.mu.Lock()
		if s.state == dnscryptServiceStopping {
			s.state = dnscryptServiceClosed
			close(done)
		}
		s.mu.Unlock()
		return shutdownErr
	default:
		s.mu.Unlock()
		return nil
	}
}

func (s *DNSCryptService) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.shutdown(ctx)
}

func (s *DNSCryptService) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.state == dnscryptServiceClosed {
		s.mu.Unlock()
		return nil
	}
	if s.state == dnscryptServiceNew {
		if len(s.servers) > 0 {
			s.rollbackBoundServersLocked()
		}
		s.state = dnscryptServiceClosed
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.shutdown(ctx)
}

func (s *DNSCryptService) Config() DNSCryptConfig {
	return s.config
}

func (s *DNSCryptService) Stamp() (string, error) {
	if !s.config.Enabled {
		return "", errors.New("DNSCrypt is disabled")
	}
	stamp, err := s.resolverConfig.CreateStamp(s.config.Listens[0])
	if err != nil {
		return "", err
	}
	return stamp.String(), nil
}

func (s *DNSCryptService) Status() DNSCryptStatus {
	status := DNSCryptStatus{Enabled: s.config.Enabled, Listens: append([]string(nil), s.config.Listens...), ProviderName: s.config.ProviderName}
	s.mu.Lock()
	status.Running = status.Enabled && s.state == dnscryptServiceRunning
	s.mu.Unlock()
	if status.Enabled {
		status.Stamp, _ = s.Stamp()
	}
	return status
}

func (s *DNSCryptService) serveDNSCrypt(ctx context.Context, writer dnscrypt.ResponseWriter, request *dns.Msg) error {
	adapter := &dnscryptDNSResponseWriter{ctx: ctx, writer: writer}
	s.server.ServeDNS(adapter, request)
	return nil
}

type dnscryptDNSResponseWriter struct {
	ctx     context.Context
	writer  dnscrypt.ResponseWriter
	written bool
}

func (w *dnscryptDNSResponseWriter) LocalAddr() net.Addr  { return w.writer.LocalAddr() }
func (w *dnscryptDNSResponseWriter) RemoteAddr() net.Addr { return w.writer.RemoteAddr() }

func (w *dnscryptDNSResponseWriter) WriteMsg(message *dns.Msg) error {
	if message == nil {
		return errors.New("DNSCrypt response is nil")
	}
	if w.written {
		return errors.New("DNSCrypt response already written")
	}
	w.written = true
	return w.writer.WriteMsg(w.ctx, message)
}

func (w *dnscryptDNSResponseWriter) Write(payload []byte) (int, error) {
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return 0, err
	}
	if err := w.WriteMsg(message); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (w *dnscryptDNSResponseWriter) TsigStatus() error   { return nil }
func (w *dnscryptDNSResponseWriter) TsigTimersOnly(bool) {}
func (w *dnscryptDNSResponseWriter) Hijack()             {}
func (w *dnscryptDNSResponseWriter) Close() error        { return nil }

var _ dns.ResponseWriter = (*dnscryptDNSResponseWriter)(nil)
