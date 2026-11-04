package app

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

// startAnswerServer answers every A query with ip and counts the queries.
func startAnswerServer(t *testing.T, ip net.IP) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int32)
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		count.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
		}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String(), count
}

func newRoutingServer(t *testing.T, config *Config) *DNSServer {
	t.Helper()
	rulesFile := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(rulesFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := rules.NewStore(rulesFile)
	config.RulesFile = rulesFile
	config.CacheEnabled, config.CacheSize = true, 1<<20
	server := &DNSServer{
		config: config, rules: store, cache: cache.New(config.CacheSize, true), logs: querylog.New(50),
		client: &dns.Client{Net: "udp", Timeout: time.Second},
		pool:   NewUpstreamPool(config.Upstreams), dnssecCacheOK: map[string]struct{}{},
	}
	server.setUpstreamRoutes(config.UpstreamRoutes)
	server.setLocalRecords(config.LocalRecords)
	return server
}

func query(server *DNSServer, name string, qtype uint16) *dns.Msg {
	writer := new(captureResponseWriter)
	server.ServeDNS(writer, newTestRequest(name, qtype))
	return writer.response
}

func TestRoutedDomainsUseTheirOwnUpstreams(t *testing.T) {
	publicAddress, publicCount := startAnswerServer(t, net.IPv4(203, 0, 113, 1))
	internalAddress, internalCount := startAnswerServer(t, net.IPv4(10, 0, 0, 5))
	config := &Config{
		Upstreams:      []string{publicAddress},
		UpstreamRoutes: []UpstreamRoute{{Name: "corp", Domains: []string{"Corp.Example."}, Upstreams: []string{internalAddress}}},
	}
	if err := validateUpstreamRoutes(config.UpstreamRoutes); err != nil {
		t.Fatal(err)
	}
	config.Access.RebindingProtection = true
	server := newRoutingServer(t, config)
	server.configureAccess(config.Access)

	response := query(server, "git.corp.example.", dns.TypeA)
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "10.0.0.5" {
		t.Fatalf("routed answer (private address must not be blocked by rebinding protection): %v", response)
	}
	if got := query(server, "www.example.org.", dns.TypeA); len(got.Answer) != 1 || got.Answer[0].(*dns.A).A.String() != "203.0.113.1" {
		t.Fatalf("default answer: %v", got)
	}
	if internalCount.Load() != 1 || publicCount.Load() != 1 {
		t.Fatalf("internal=%d public=%d queries, want 1 and 1", internalCount.Load(), publicCount.Load())
	}
	if status := server.routeStatus(); len(status) != 1 || status[0].Upstreams[0].Requests != 1 {
		t.Fatalf("route status = %#v", status)
	}
}

func TestRoutedDomainNeverFallsBackToPublicUpstreams(t *testing.T) {
	publicAddress, publicCount := startAnswerServer(t, net.IPv4(203, 0, 113, 1))
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := dead.LocalAddr().String()
	_ = dead.Close()
	config := &Config{
		Upstreams:         []string{publicAddress},
		FallbackUpstreams: []string{publicAddress},
		UpstreamRoutes:    []UpstreamRoute{{Domains: []string{"corp.example"}, Upstreams: []string{deadAddress}}},
	}
	server := newRoutingServer(t, config)
	response := query(server, "git.corp.example.", dns.TypeA)
	if response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", response.Rcode)
	}
	if publicCount.Load() != 0 {
		t.Fatal("internal name leaked to the public upstream")
	}
}

func TestMostSpecificRouteWins(t *testing.T) {
	table := buildRouteTable([]UpstreamRoute{
		{Domains: []string{"example.com"}, Upstreams: []string{"1.1.1.1:53"}},
		{Domains: []string{"lab.example.com"}, Upstreams: []string{"10.0.0.1:53"}},
	}, nil)
	if route := table.lookup("a.lab.example.com."); route == nil || route.config.Upstreams[0] != "10.0.0.1:53" {
		t.Fatalf("lookup = %#v", route)
	}
	if route := table.lookup("www.example.com"); route == nil || route.config.Upstreams[0] != "1.1.1.1:53" {
		t.Fatalf("lookup = %#v", route)
	}
	if table.lookup("example.org") != nil || (*routeTable)(nil).lookup("x") != nil {
		t.Fatal("unexpected route")
	}
}

func TestValidateUpstreamRoutes(t *testing.T) {
	bad := map[string][]UpstreamRoute{
		"no domains":   {{Upstreams: []string{"10.0.0.1:53"}}},
		"no upstreams": {{Domains: []string{"a.test"}}},
		"bad domain":   {{Domains: []string{"not a domain"}, Upstreams: []string{"10.0.0.1:53"}}},
		"bad upstream": {{Domains: []string{"a.test"}, Upstreams: []string{"://"}}},
		"duplicate":    {{Domains: []string{"a.test"}, Upstreams: []string{"10.0.0.1:53"}}, {Domains: []string{"A.test."}, Upstreams: []string{"10.0.0.2:53"}}},
	}
	for name, routes := range bad {
		if err := validateUpstreamRoutes(routes); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	routes := []UpstreamRoute{{Domains: []string{" *.Corp.Example. "}, Upstreams: []string{"10.0.0.1:53"}}}
	if err := validateUpstreamRoutes(routes); err != nil || routes[0].Domains[0] != "corp.example" {
		t.Fatalf("normalized = %#v, %v", routes, err)
	}
}

func TestPrivateReverseLookups(t *testing.T) {
	publicAddress, publicCount := startAnswerServer(t, net.IPv4(203, 0, 113, 1))
	routedAddress, routedCount := startAnswerServer(t, net.IPv4(10, 0, 0, 9))
	config := &Config{
		Upstreams:      []string{publicAddress},
		PrivateReverse: true,
		LocalRecords:   []LocalRecord{{Domain: "nas.home.arpa", Type: "A", Value: "192.168.1.10", TTL: 60}},
		UpstreamRoutes: []UpstreamRoute{{Domains: []string{"2.0.10.in-addr.arpa"}, Upstreams: []string{routedAddress}}},
	}
	server := newRoutingServer(t, config)

	if response := query(server, "10.1.168.192.in-addr.arpa.", dns.TypePTR); len(response.Answer) != 1 || response.Answer[0].(*dns.PTR).Ptr != "nas.home.arpa." {
		t.Fatalf("derived PTR: %v", response)
	}
	if response := query(server, "99.1.168.192.in-addr.arpa.", dns.TypePTR); response.Rcode != dns.RcodeNameError {
		t.Fatalf("private PTR should be NXDOMAIN, got %v", response)
	}
	query(server, "7.2.0.10.in-addr.arpa.", dns.TypePTR) // routed private zone goes to its upstream
	query(server, "8.8.8.8.in-addr.arpa.", dns.TypePTR)  // public reverse zone goes to the default upstream
	if publicCount.Load() != 1 || routedCount.Load() != 1 {
		t.Fatalf("public=%d routed=%d, want 1 and 1", publicCount.Load(), routedCount.Load())
	}
}

func TestIsPrivateReverseName(t *testing.T) {
	for name, want := range map[string]bool{
		"1.0.0.10.in-addr.arpa":  true,
		"10.in-addr.arpa":        true,
		"168.192.in-addr.arpa":   true,
		"16.172.in-addr.arpa":    true,
		"31.172.in-addr.arpa":    true,
		"32.172.in-addr.arpa":    false,
		"254.169.in-addr.arpa":   true,
		"1.0.0.127.in-addr.arpa": true,
		"8.8.8.8.in-addr.arpa":   false,
		"192.in-addr.arpa":       false,
		"d.f.ip6.arpa":           true,
		"c.f.ip6.arpa":           true,
		"8.e.f.ip6.arpa":         true,
		"c.e.f.ip6.arpa":         false,
		"b.d.0.1.0.0.2.ip6.arpa": false,
		"example.com":            false,
		"x.in-addr.arpa":         false,
		"1.2.3.4.5.in-addr.arpa": false,
	} {
		if got := isPrivateReverseName(name); got != want {
			t.Errorf("isPrivateReverseName(%q) = %v, want %v", name, got, want)
		}
	}
	loopback := "1." + "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" + ".ip6.arpa"
	if !isPrivateReverseName(loopback) {
		t.Error("::1 should be private")
	}
}

func TestBlockAAAAAnswersLocallyButKeepsLocalRecords(t *testing.T) {
	publicAddress, publicCount := startAnswerServer(t, net.IPv4(203, 0, 113, 1))
	config := &Config{
		Upstreams: []string{publicAddress}, BlockAAAA: true, BlockedResponseTTL: 30,
		LocalRecords: []LocalRecord{{Domain: "v6.home.arpa", Type: "AAAA", Value: "fd00::1", TTL: 60}},
	}
	server := newRoutingServer(t, config)
	response := query(server, "www.example.org.", dns.TypeAAAA)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 || len(response.Ns) != 1 {
		t.Fatalf("AAAA should be an empty NOERROR with SOA: %v", response)
	}
	if publicCount.Load() != 0 {
		t.Fatal("AAAA query reached the upstream")
	}
	if got := query(server, "v6.home.arpa.", dns.TypeAAAA); len(got.Answer) != 1 {
		t.Fatalf("local AAAA record must still be answered: %v", got)
	}
	if got := query(server, "www.example.org.", dns.TypeA); len(got.Answer) != 1 {
		t.Fatalf("A queries are unaffected: %v", got)
	}
}
