package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type secureServiceState uint8

const (
	secureServiceNew secureServiceState = iota
	secureServiceBound
	secureServiceRunning
	secureServiceStopping
	secureServiceClosed
)

// SecureDNSService owns all inbound DoT, DoH, DoH3 and DoQ resources. It does not
// modify DNSServer configuration and delegates every DNS query to ServeDNS.
type SecureDNSService struct {
	server *DNSServer
	config EncryptionConfig

	mu          sync.Mutex
	lifecycleMu sync.Mutex
	state       secureServiceState
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	doqConns    map[*quic.Conn]struct{}

	// The singular fields are retained for compatibility with existing tests and
	// status inspection; they always point to the first listener of each type.
	dotListener  net.Listener
	dohListener  net.Listener
	doh3Listener *quic.Listener
	doqListener  *quic.Listener

	dotListeners  []net.Listener
	dohListeners  []net.Listener
	doh3Listeners []*quic.Listener
	doqListeners  []*quic.Listener
	dotServers    []*dns.Server
	dohServers    []*http.Server
	doh3Servers   []*http3.Server
	dotServer     *dns.Server
	dohServer     *http.Server
	doh3Server    *http3.Server
	dnscrypt      *DNSCryptService
}

func NewSecureDNSService(server *DNSServer, config EncryptionConfig) (*SecureDNSService, error) {
	if server == nil {
		return nil, errors.New("secure DNS service requires a DNS server")
	}
	if config.Enabled {
		if err := normalizeEncryptionListeners(&config); err != nil {
			return nil, err
		}
	}
	if err := validateEncryptionConfig(config); err != nil {
		return nil, err
	}
	service := &SecureDNSService{server: server, config: config, state: secureServiceNew, doqConns: make(map[*quic.Conn]struct{})}
	if config.DNSCrypt.Enabled {
		dnscryptService, err := NewDNSCryptService(server, config.DNSCrypt)
		if err != nil {
			return nil, err
		}
		service.dnscrypt = dnscryptService
		service.config.DNSCrypt = dnscryptService.config
	}
	return service, nil
}

// Bind validates and binds every enabled listener without starting any accept
// loop. If one bind fails, all listeners already acquired by this service are
// closed before the error is returned.
func (s *SecureDNSService) Bind() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != secureServiceNew {
		return fmt.Errorf("secure DNS service cannot bind in state %d", s.state)
	}
	if s.config.Enabled {
		if err := normalizeEncryptionListeners(&s.config); err != nil {
			return err
		}
	}
	if err := validateEncryptionConfig(s.config); err != nil {
		return err
	}
	if s.doqConns == nil {
		s.doqConns = make(map[*quic.Conn]struct{})
	}
	if !s.config.Enabled {
		if s.dnscrypt != nil {
			if err := s.dnscrypt.Bind(); err != nil {
				return err
			}
		}
		s.state = secureServiceBound
		return nil
	}
	certificate, err := loadServerCertificate(s.config)
	if err != nil {
		return fmt.Errorf("load encryption certificate and private key: %w", err)
	}
	baseTLS := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			current, loadErr := loadServerCertificate(s.config)
			if loadErr != nil {
				return nil, loadErr
			}
			return &current, nil
		},
	}

	closeBound := func(bindErr error) error {
		s.closeBoundListenersLocked()
		if s.dnscrypt != nil {
			_ = s.dnscrypt.Close()
		}
		return bindErr
	}

	if s.dnscrypt != nil {
		if err := s.dnscrypt.Bind(); err != nil {
			return closeBound(err)
		}
	}
	if !s.config.Enabled {
		s.state = secureServiceBound
		return nil
	}
	for _, address := range s.config.DoTListens {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			return closeBound(fmt.Errorf("DoT cannot listen on %s: %w", address, listenErr))
		}
		tlsListener := tls.NewListener(listener, cloneTLSConfig(baseTLS, []string{"dot"}))
		s.dotListeners = append(s.dotListeners, tlsListener)
		s.dotServers = append(s.dotServers, &dns.Server{Listener: tlsListener, Handler: s.server})
	}

	for _, address := range s.config.DoHListens {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			return closeBound(fmt.Errorf("DoH cannot listen on %s: %w", address, listenErr))
		}
		tlsListener := tls.NewListener(listener, cloneTLSConfig(baseTLS, []string{"h2", "http/1.1"}))
		s.dohListeners = append(s.dohListeners, tlsListener)
		s.dohServers = append(s.dohServers, &http.Server{
			Handler:           s.doHHandler(),
			ReadHeaderTimeout: httpReadHeaderTimeout,
			ReadTimeout:       httpReadTimeout,
			WriteTimeout:      httpWriteTimeout,
			IdleTimeout:       httpIdleTimeout,
			MaxHeaderBytes:    httpMaxHeaderBytes,
		})
	}

	for _, address := range s.config.DoH3Listens {
		doh3TLS := http3.ConfigureTLSConfig(cloneTLSConfig(baseTLS, []string{http3.NextProtoH3}))
		doh3TLS.MinVersion = tls.VersionTLS13
		listener, listenErr := quic.ListenAddr(address, doh3TLS, &quic.Config{
			HandshakeIdleTimeout:  5 * time.Second,
			MaxIdleTimeout:        secureDoH3IdleTimeout,
			MaxIncomingStreams:    100,
			MaxIncomingUniStreams: 10,
		})
		if listenErr != nil {
			return closeBound(fmt.Errorf("DoH3 cannot listen on %s: %w", address, listenErr))
		}
		s.doh3Listeners = append(s.doh3Listeners, listener)
		s.doh3Servers = append(s.doh3Servers, &http3.Server{
			TLSConfig:      doh3TLS,
			Handler:        http.TimeoutHandler(s.doHHandler(), secureDoH3RequestTimeout, "DNS request timed out"),
			MaxHeaderBytes: httpMaxHeaderBytes,
			IdleTimeout:    secureDoH3IdleTimeout,
		})
	}

	for _, address := range s.config.DoQListens {
		doqTLS := cloneTLSConfig(baseTLS, []string{"doq"})
		doqTLS.MinVersion = tls.VersionTLS13
		listener, listenErr := quic.ListenAddr(address, doqTLS, &quic.Config{
			MaxIdleTimeout:        secureDoQIdleTimeout,
			MaxIncomingStreams:    100,
			MaxIncomingUniStreams: 0,
		})
		if listenErr != nil {
			return closeBound(fmt.Errorf("DoQ cannot listen on %s: %w", address, listenErr))
		}
		s.doqListeners = append(s.doqListeners, listener)
	}
	s.dotListener = firstNetListener(s.dotListeners)
	s.dohListener = firstNetListener(s.dohListeners)
	s.doh3Listener = firstQUICListener(s.doh3Listeners)
	s.doqListener = firstQUICListener(s.doqListeners)
	s.dotServer = firstDNSServer(s.dotServers)
	s.dohServer = firstHTTPServer(s.dohServers)
	s.doh3Server = firstHTTP3Server(s.doh3Servers)

	s.state = secureServiceBound
	return nil
}

func cloneTLSConfig(config *tls.Config, protocols []string) *tls.Config {
	clone := config.Clone()
	clone.NextProtos = append([]string(nil), protocols...)
	return clone
}

func firstNetListener(listeners []net.Listener) net.Listener {
	if len(listeners) == 0 {
		return nil
	}
	return listeners[0]
}

func firstQUICListener(listeners []*quic.Listener) *quic.Listener {
	if len(listeners) == 0 {
		return nil
	}
	return listeners[0]
}

func firstDNSServer(servers []*dns.Server) *dns.Server {
	if len(servers) == 0 {
		return nil
	}
	return servers[0]
}

func firstHTTPServer(servers []*http.Server) *http.Server {
	if len(servers) == 0 {
		return nil
	}
	return servers[0]
}

func firstHTTP3Server(servers []*http3.Server) *http3.Server {
	if len(servers) == 0 {
		return nil
	}
	return servers[0]
}

func (s *SecureDNSService) closeBoundListenersLocked() {
	for _, listener := range s.dotListeners {
		_ = listener.Close()
	}
	for _, listener := range s.dohListeners {
		_ = listener.Close()
	}
	for _, listener := range s.doh3Listeners {
		_ = listener.Close()
	}
	for _, listener := range s.doqListeners {
		_ = listener.Close()
	}
	s.dotListeners = nil
	s.dohListeners = nil
	s.doh3Listeners = nil
	s.doqListeners = nil
	s.dotServers = nil
	s.dohServers = nil
	s.doh3Servers = nil
	s.dotServer = nil
	s.dohServer = nil
	s.doh3Server = nil
	s.dotListener = nil
	s.dohListener = nil
	s.doh3Listener = nil
	s.doqListener = nil
}

// Start starts previously bound listeners. Context cancellation stops the
// service, while Shutdown can be used when a graceful deadline is available.
func (s *SecureDNSService) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	s.mu.Lock()
	if s.state != secureServiceBound {
		state := s.state
		s.mu.Unlock()
		s.lifecycleMu.Unlock()
		return fmt.Errorf("secure DNS service must be bound before start (state %d)", state)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.state = secureServiceRunning
	dotServers := append([]*dns.Server(nil), s.dotServers...)
	dohListeners := append([]net.Listener(nil), s.dohListeners...)
	dohServers := append([]*http.Server(nil), s.dohServers...)
	doh3Listeners := append([]*quic.Listener(nil), s.doh3Listeners...)
	doh3Servers := append([]*http3.Server(nil), s.doh3Servers...)
	doqListeners := append([]*quic.Listener(nil), s.doqListeners...)
	dnscryptService := s.dnscrypt
	s.mu.Unlock()

	for _, server := range dotServers {
		s.wg.Add(1)
		go s.serveDoT(server)
	}
	for index, server := range dohServers {
		if index >= len(dohListeners) {
			break
		}
		s.wg.Add(1)
		go s.serveDoH(server, dohListeners[index])
	}
	for index, server := range doh3Servers {
		if index >= len(doh3Listeners) {
			break
		}
		s.wg.Add(1)
		go s.serveDoH3(server, doh3Listeners[index])
	}
	for _, listener := range doqListeners {
		s.wg.Add(1)
		go s.serveDoQ(runCtx, listener)
	}
	if dnscryptService != nil {
		if err := dnscryptService.Start(runCtx); err != nil {
			s.lifecycleMu.Unlock()
			_ = s.Close()
			return err
		}
	}
	go func() {
		<-runCtx.Done()
		_ = s.Shutdown(context.Background())
	}()
	s.lifecycleMu.Unlock()
	return nil
}

func (s *SecureDNSService) serveDoT(server *dns.Server) {
	defer s.wg.Done()
	if err := server.ActivateAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
		// The owning process reports listener failures through its normal logs;
		// a failed accept loop must not bring down the other protocols.
	}
}

func (s *SecureDNSService) serveDoH(server *http.Server, listener net.Listener) {
	defer s.wg.Done()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		// See serveDoT: the listener is owned by this service and is closed by
		// Shutdown/Close.
	}
}

func (s *SecureDNSService) serveDoH3(server *http3.Server, listener *quic.Listener) {
	defer s.wg.Done()
	if err := server.ServeListener(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		// The listener is owned by this service and is closed by Shutdown/Close.
	}
}

// Shutdown stops accepts, gracefully drains DoH and DoH3 requests, and waits for all
// service goroutines until ctx expires. It is safe to call repeatedly.
func (s *SecureDNSService) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	if s.state == secureServiceClosed || s.state == secureServiceNew {
		s.mu.Unlock()
		return nil
	}
	if s.state == secureServiceStopping {
		s.mu.Unlock()
		return s.wait(ctx)
	}
	s.state = secureServiceStopping
	cancel := s.cancel
	dotListeners := append([]net.Listener(nil), s.dotListeners...)
	dohListeners := append([]net.Listener(nil), s.dohListeners...)
	doh3Listeners := append([]*quic.Listener(nil), s.doh3Listeners...)
	doqListeners := append([]*quic.Listener(nil), s.doqListeners...)
	dotServers := append([]*dns.Server(nil), s.dotServers...)
	dohServers := append([]*http.Server(nil), s.dohServers...)
	doh3Servers := append([]*http3.Server(nil), s.doh3Servers...)
	dnscryptService := s.dnscrypt
	connections := make([]*quic.Conn, 0, len(s.doqConns))
	for connection := range s.doqConns {
		connections = append(connections, connection)
	}
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, listener := range dotListeners {
		_ = listener.Close()
	}
	for _, listener := range dohListeners {
		_ = listener.Close()
	}
	for _, listener := range doqListeners {
		_ = listener.Close()
	}
	for _, connection := range connections {
		_ = connection.CloseWithError(0, "server is stopping")
	}

	serverCount := len(dotServers) + len(dohServers) + len(doh3Servers)
	shutdownErrors := make(chan error, serverCount)
	var shutdownWG sync.WaitGroup
	for _, server := range dotServers {
		shutdownWG.Add(1)
		go func(server *dns.Server) {
			defer shutdownWG.Done()
			shutdownErrors <- server.Shutdown()
		}(server)
	}
	for _, server := range dohServers {
		shutdownWG.Add(1)
		go func(server *http.Server) {
			defer shutdownWG.Done()
			shutdownErrors <- server.Shutdown(ctx)
		}(server)
	}
	for index, server := range doh3Servers {
		if index >= len(doh3Listeners) {
			break
		}
		shutdownWG.Add(1)
		go func(server *http3.Server, listener *quic.Listener) {
			defer shutdownWG.Done()
			shutdownErr := server.Shutdown(ctx)
			_ = server.Close()
			_ = listener.Close()
			shutdownErrors <- shutdownErr
		}(server, doh3Listeners[index])
	}
	shutdownDone := make(chan struct{})
	go func() {
		shutdownWG.Wait()
		s.wg.Wait()
		close(shutdownDone)
	}()

	var dnscryptErr error
	if dnscryptService != nil {
		dnscryptErr = dnscryptService.Shutdown(ctx)
	}
	select {
	case <-shutdownDone:
		s.mu.Lock()
		if s.state == secureServiceStopping {
			s.state = secureServiceClosed
		}
		s.mu.Unlock()
		var listenerErr error
		for index := 0; index < serverCount; index++ {
			listenerErr = errors.Join(listenerErr, <-shutdownErrors)
		}
		return errors.Join(dnscryptErr, listenerErr)
	case <-ctx.Done():
		_ = s.Close()
		return errors.Join(dnscryptErr, ctx.Err())
	}
}

func (s *SecureDNSService) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.mu.Lock()
		if s.state == secureServiceStopping {
			s.state = secureServiceClosed
		}
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	}
}

// Close immediately releases all listener and connection resources. It is
// safe to call after Bind, Start, or Shutdown, and may be called repeatedly.
func (s *SecureDNSService) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	if s.state == secureServiceClosed {
		s.mu.Unlock()
		return nil
	}
	s.state = secureServiceClosed
	cancel := s.cancel
	dohServers := append([]*http.Server(nil), s.dohServers...)
	doh3Servers := append([]*http3.Server(nil), s.doh3Servers...)
	dnscryptService := s.dnscrypt
	connections := make([]*quic.Conn, 0, len(s.doqConns))
	for connection := range s.doqConns {
		connections = append(connections, connection)
	}
	s.closeBoundListenersLocked()
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, server := range dohServers {
		_ = server.Close()
	}
	for _, server := range doh3Servers {
		_ = server.Close()
	}
	if dnscryptService != nil {
		_ = dnscryptService.Close()
	}
	for _, connection := range connections {
		_ = connection.CloseWithError(0, "server is closed")
	}
	return nil
}
