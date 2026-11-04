package app

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingUpstream answers every A query and records the source port of each.
// With dup set it sends every answer twice, like a misbehaving upstream.
type countingUpstream struct {
	conn  net.PacketConn
	mu    sync.Mutex
	ports []int
	dup   bool
}

func newCountingUpstream(t *testing.T, dup bool) *countingUpstream {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &countingUpstream{conn: conn, dup: dup}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			request := new(dns.Msg)
			if request.Unpack(buf[:n]) != nil {
				continue
			}
			u.mu.Lock()
			u.ports = append(u.ports, from.(*net.UDPAddr).Port)
			u.mu.Unlock()
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
			packet, _ := response.Pack()
			_, _ = conn.WriteTo(packet, from)
			if u.dup {
				_, _ = conn.WriteTo(packet, from)
			}
		}
	}()
	return u
}

func (u *countingUpstream) distinctPorts() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	seen := map[int]bool{}
	for _, port := range u.ports {
		seen[port] = true
	}
	return len(seen)
}

func queryOnce(t *testing.T, s *DNSServer, upstream, name string) {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, dns.TypeA)
	response, err := s.exchangeUpstream(request, upstream)
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("query %s: %v %v", name, response, err)
	}
}

func newPoolTestServer() *DNSServer {
	return &DNSServer{client: &dns.Client{Net: "udp", Timeout: time.Second}}
}

func TestUDPSocketsAreReusedAndRecycled(t *testing.T) {
	upstream := newCountingUpstream(t, false)
	s := newPoolTestServer()
	defer s.udpPool.closeAll()
	address := upstream.conn.LocalAddr().String()
	for i := 0; i < 10; i++ {
		queryOnce(t, s, address, "a.test.")
	}
	if got := upstream.distinctPorts(); got != 1 {
		t.Fatalf("sequential queries used %d source ports, want 1 (reuse)", got)
	}
	for i := 0; i < maxUDPUses; i++ {
		queryOnce(t, s, address, "a.test.")
	}
	if got := upstream.distinctPorts(); got < 2 {
		t.Fatalf("a socket was used for %d queries without being replaced", 10+maxUDPUses)
	}
}

func TestStrayDatagramInReusedSocketIsDiscarded(t *testing.T) {
	upstream := newCountingUpstream(t, true) // every answer arrives twice
	s := newPoolTestServer()
	defer s.udpPool.closeAll()
	address := upstream.conn.LocalAddr().String()
	for i := 0; i < 5; i++ {
		queryOnce(t, s, address, "b.test.")
		time.Sleep(20 * time.Millisecond) // let the duplicate arrive
	}
}

func TestFailedExchangeDoesNotReturnSocketToPool(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() // never answers
	s := &DNSServer{client: &dns.Client{Net: "udp", Timeout: 100 * time.Millisecond}}
	defer s.udpPool.closeAll()
	request := new(dns.Msg)
	request.SetQuestion("c.test.", dns.TypeA)
	if _, err := s.exchangeUpstream(request, conn.LocalAddr().String()); err == nil {
		t.Fatal("expected a timeout")
	}
	if s.udpPool.total != 0 {
		t.Fatalf("pool holds %d sockets after a failed exchange", s.udpPool.total)
	}
}
