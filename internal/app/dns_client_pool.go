package app

import (
	"errors"
	"net/http"
	"sync"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type dohClientEntry struct {
	client    *http.Client
	transport *http.Transport
	refs      int
	retired   bool
}

type doh3ClientEntry struct {
	client    *http.Client
	transport *http3.Transport
	refs      int
	retired   bool
}

type dotClientEntry struct {
	server   *DNSServer
	hostname string
	port     string
	client   *dns.Client

	exchangeMu sync.Mutex
	stateMu    sync.Mutex
	conn       *dns.Conn
	retired    bool
}

type doqClientEntry struct {
	server   *DNSServer
	hostname string
	port     string

	dialMu  sync.Mutex
	stateMu sync.Mutex
	conn    *quic.Conn
	retired bool
}

type dnscryptClientEntry struct {
	server *DNSServer
	stamp  string
	proto  dnscrypt.Proto
	client *dnscrypt.Client

	mu      sync.Mutex
	info    *dnscrypt.ResolverInfo
	retired bool
}

func (s *DNSServer) closeDoHClients() bool {
	s.dohMu.Lock()
	if s.dohClosed {
		s.dohMu.Unlock()
		return false
	}
	s.dohClosed = true
	oldDoH := s.dohClients
	s.dohClients = make(map[string]*dohClientEntry)
	for _, entry := range oldDoH {
		entry.retired = true
	}
	s.dohMu.Unlock()

	for _, entry := range oldDoH {
		entry.transport.CloseIdleConnections()
	}
	return true
}

func (s *DNSServer) closeDNSCryptClients() {
	s.dnscryptMu.Lock()
	s.dnscryptClosed = true
	oldDNSCrypt := s.dnscryptClients
	s.dnscryptClients = make(map[string]*dnscryptClientEntry)
	s.dnscryptMu.Unlock()

	for _, entry := range oldDNSCrypt {
		entry.close()
	}
}

func (s *DNSServer) closeEncryptedClients() {
	s.encryptedMu.Lock()
	s.encryptedClosed = true
	oldDoT := s.dotClients
	oldDoQ := s.doqClients
	s.dotClients = make(map[string]*dotClientEntry)
	s.doqClients = make(map[string]*doqClientEntry)
	s.encryptedMu.Unlock()

	for _, entry := range oldDoT {
		entry.close()
	}
	for _, entry := range oldDoQ {
		entry.close()
	}
}

func (s *DNSServer) acquireDoHClient(origin, hostname, port string) (*dohClientEntry, error) {
	s.dohMu.Lock()
	defer s.dohMu.Unlock()
	if s.dohClosed {
		return nil, errors.New("DNS server is closed")
	}
	if s.dohClients == nil {
		s.dohClients = make(map[string]*dohClientEntry)
	}
	if entry := s.dohClients[origin]; entry != nil {
		entry.refs++
		return entry, nil
	}
	entry := newDoHClientEntry(s, hostname, port)
	entry.refs = 1
	s.dohClients[origin] = entry
	return entry, nil
}

func (s *DNSServer) releaseDoHClient(entry *dohClientEntry) {
	if entry == nil {
		return
	}
	s.dohMu.Lock()
	if entry.refs > 0 {
		entry.refs--
	}
	shouldClose := entry.retired && entry.refs == 0
	s.dohMu.Unlock()
	if shouldClose {
		entry.transport.CloseIdleConnections()
	}
}

func (s *DNSServer) invalidateDoHClients() {
	s.dohMu.Lock()
	old := s.dohClients
	s.dohClients = make(map[string]*dohClientEntry)
	for _, entry := range old {
		entry.retired = true
	}
	s.dohMu.Unlock()

	for _, entry := range old {
		entry.transport.CloseIdleConnections()
	}
}

func (s *DNSServer) invalidateDNSCryptClients() {
	s.dnscryptMu.Lock()
	old := s.dnscryptClients
	s.dnscryptClients = make(map[string]*dnscryptClientEntry)
	s.dnscryptMu.Unlock()
	for _, entry := range old {
		entry.close()
	}
}
func (s *DNSServer) invalidateEncryptedClients() {
	s.encryptedMu.Lock()
	oldDoT := s.dotClients
	oldDoQ := s.doqClients
	s.dotClients = make(map[string]*dotClientEntry)
	s.doqClients = make(map[string]*doqClientEntry)
	s.encryptedMu.Unlock()

	for _, entry := range oldDoT {
		entry.close()
	}
	for _, entry := range oldDoQ {
		entry.close()
	}
}

func (s *DNSServer) acquireDoTClient(endpoint, hostname, port string) (*dotClientEntry, error) {
	s.encryptedMu.Lock()
	defer s.encryptedMu.Unlock()
	if s.encryptedClosed {
		return nil, errors.New("DNS server is closed")
	}
	if s.dotClients == nil {
		s.dotClients = make(map[string]*dotClientEntry)
	}
	if entry := s.dotClients[endpoint]; entry != nil {
		return entry, nil
	}
	entry := newDoTClientEntry(s, hostname, port)
	s.dotClients[endpoint] = entry
	return entry, nil
}

func (s *DNSServer) acquireDoQClient(endpoint, hostname, port string) (*doqClientEntry, error) {
	s.encryptedMu.Lock()
	defer s.encryptedMu.Unlock()
	if s.encryptedClosed {
		return nil, errors.New("DNS server is closed")
	}
	if s.doqClients == nil {
		s.doqClients = make(map[string]*doqClientEntry)
	}
	if entry := s.doqClients[endpoint]; entry != nil {
		return entry, nil
	}
	entry := newDoQClientEntry(s, hostname, port)
	s.doqClients[endpoint] = entry
	return entry, nil
}

func (s *DNSServer) acquireDoH3Client(origin, hostname, port string) (*doh3ClientEntry, error) {
	s.doh3Mu.Lock()
	defer s.doh3Mu.Unlock()
	if s.doh3Closed {
		return nil, errors.New("DNS server is closed")
	}
	if s.doh3Clients == nil {
		s.doh3Clients = make(map[string]*doh3ClientEntry)
	}
	if entry := s.doh3Clients[origin]; entry != nil {
		entry.refs++
		return entry, nil
	}
	entry := newDoH3ClientEntry(s, hostname, port)
	entry.refs = 1
	s.doh3Clients[origin] = entry
	return entry, nil
}

func (s *DNSServer) releaseDoH3Client(entry *doh3ClientEntry) {
	if entry == nil {
		return
	}
	s.doh3Mu.Lock()
	if entry.refs > 0 {
		entry.refs--
	}
	shouldClose := entry.retired && entry.refs == 0
	s.doh3Mu.Unlock()
	if shouldClose {
		_ = entry.transport.Close()
	}
}

func (s *DNSServer) invalidateDoH3Clients() {
	s.doh3Mu.Lock()
	old := s.doh3Clients
	s.doh3Clients = make(map[string]*doh3ClientEntry)
	for _, entry := range old {
		entry.retired = true
	}
	s.doh3Mu.Unlock()
	for _, entry := range old {
		entry.transport.CloseIdleConnections()
	}
}

func (s *DNSServer) closeDoH3Clients() {
	s.doh3Mu.Lock()
	if s.doh3Closed {
		s.doh3Mu.Unlock()
		return
	}
	s.doh3Closed = true
	old := s.doh3Clients
	s.doh3Clients = make(map[string]*doh3ClientEntry)
	for _, entry := range old {
		entry.retired = true
	}
	s.doh3Mu.Unlock()
	for _, entry := range old {
		_ = entry.transport.Close()
	}
}

func (s *DNSServer) acquireDNSCryptClient(stamp string, proto dnscrypt.Proto) (*dnscryptClientEntry, error) {
	s.dnscryptMu.Lock()
	defer s.dnscryptMu.Unlock()
	if s.dnscryptClosed {
		return nil, errors.New("DNS server is closed")
	}
	if s.dnscryptClients == nil {
		s.dnscryptClients = make(map[string]*dnscryptClientEntry)
	}
	key := string(proto) + "\x00" + stamp
	if entry := s.dnscryptClients[key]; entry != nil {
		return entry, nil
	}
	entry := newDNSCryptClientEntry(s, stamp, proto)
	s.dnscryptClients[key] = entry
	return entry, nil
}
