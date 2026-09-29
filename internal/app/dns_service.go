package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type dnsServiceState uint8

const (
	dnsServiceNew dnsServiceState = iota
	dnsServiceBound
	dnsServiceRunning
	dnsServiceStopping
	dnsServiceClosed
)

type dnsListenerPair struct {
	address     string
	packetConn  net.PacketConn
	tcpListener net.Listener
	udpServer   *dns.Server
	tcpServer   *dns.Server
}

// DNSService owns all ordinary DNS UDP and TCP listeners. It keeps binding and
// lifecycle coordination out of main so every address follows the same rollback
// and shutdown rules.
type DNSService struct {
	server    *DNSServer
	addresses []string

	mu          sync.Mutex
	lifecycleMu sync.Mutex
	state       dnsServiceState
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	listeners   []dnsListenerPair
}

func NewDNSService(server *DNSServer, config Config) (*DNSService, error) {
	if server == nil {
		return nil, errors.New("DNS service requires a DNS server")
	}
	addresses, err := normalizeListenAddresses("dns listen", "", config.DNSListens)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("DNS service requires at least one listen address")
	}
	return &DNSService{server: server, addresses: addresses, state: dnsServiceNew}, nil
}

// Bind acquires both transports for every configured address. A partial bind is
// never retained: any failure closes all listeners acquired so far.
func (s *DNSService) Bind() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != dnsServiceNew {
		return fmt.Errorf("DNS service cannot bind in state %d", s.state)
	}

	closeBound := func(bindErr error) error {
		s.closeListenersLocked()
		return bindErr
	}
	for _, address := range s.addresses {
		packetConn, err := net.ListenPacket("udp", address)
		if err != nil {
			return closeBound(fmt.Errorf("DNS UDP cannot listen on %s: %w", address, err))
		}
		tcpListener, err := net.Listen("tcp", address)
		if err != nil {
			_ = packetConn.Close()
			return closeBound(fmt.Errorf("DNS TCP cannot listen on %s: %w", address, err))
		}
		s.listeners = append(s.listeners, dnsListenerPair{
			address:     address,
			packetConn:  packetConn,
			tcpListener: tcpListener,
			udpServer:   &dns.Server{PacketConn: packetConn, Handler: s.server},
			tcpServer:   &dns.Server{Listener: tcpListener, Handler: s.server},
		})
	}
	s.state = dnsServiceBound
	return nil
}

func (s *DNSService) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.state != dnsServiceBound {
		state := s.state
		s.mu.Unlock()
		return fmt.Errorf("DNS service must be bound before start (state %d)", state)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.state = dnsServiceRunning
	listeners := append([]dnsListenerPair(nil), s.listeners...)
	s.mu.Unlock()

	for _, listener := range listeners {
		s.wg.Add(2)
		go s.serve(listener.udpServer)
		go s.serve(listener.tcpServer)
	}
	go func() {
		<-runCtx.Done()
		_ = s.Shutdown(context.Background())
	}()
	return nil
}

func (s *DNSService) serve(server *dns.Server) {
	defer s.wg.Done()
	if err := server.ActivateAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Error("DNS listener stopped", "error", err)
	}
}

func (s *DNSService) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.addresses...)
}

func (s *DNSService) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.listeners) > 0 && (s.state == dnsServiceBound || s.state == dnsServiceRunning)
}

func (s *DNSService) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.state == dnsServiceNew || s.state == dnsServiceClosed {
		s.mu.Unlock()
		return nil
	}
	if s.state == dnsServiceStopping {
		s.mu.Unlock()
		return s.wait(ctx)
	}
	s.state = dnsServiceStopping
	cancel := s.cancel
	listeners := append([]dnsListenerPair(nil), s.listeners...)
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	shutdownDone := make(chan struct{})
	shutdownErrors := make(chan error, len(listeners)*2)
	var shutdownWG sync.WaitGroup
	for _, listener := range listeners {
		for _, server := range []*dns.Server{listener.udpServer, listener.tcpServer} {
			shutdownWG.Add(1)
			go func(server *dns.Server) {
				defer shutdownWG.Done()
				shutdownErrors <- server.Shutdown()
			}(server)
		}
	}
	go func() {
		shutdownWG.Wait()
		s.wg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		s.mu.Lock()
		if s.state == dnsServiceStopping {
			s.state = dnsServiceClosed
		}
		s.mu.Unlock()
		return collectDNSServerShutdownErrors(shutdownErrors, len(listeners)*2)
	case <-ctx.Done():
		s.mu.Lock()
		s.closeListenersLocked()
		s.state = dnsServiceClosed
		s.mu.Unlock()
		return ctx.Err()
	}
}

func collectDNSServerShutdownErrors(errorsChannel <-chan error, count int) error {
	var shutdownErr error
	for index := 0; index < count; index++ {
		shutdownErr = errors.Join(shutdownErr, <-errorsChannel)
	}
	return shutdownErr
}

func (s *DNSService) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.mu.Lock()
		if s.state == dnsServiceStopping {
			s.state = dnsServiceClosed
		}
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		s.closeListenersLocked()
		s.state = dnsServiceClosed
		s.mu.Unlock()
		return ctx.Err()
	}
}

func (s *DNSService) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.state == dnsServiceClosed {
		s.mu.Unlock()
		return nil
	}
	s.state = dnsServiceClosed
	if s.cancel != nil {
		s.cancel()
	}
	s.closeListenersLocked()
	s.mu.Unlock()
	return nil
}

func (s *DNSService) closeListenersLocked() {
	for _, listener := range s.listeners {
		_ = listener.packetConn.Close()
		_ = listener.tcpListener.Close()
	}
	s.listeners = nil
}
