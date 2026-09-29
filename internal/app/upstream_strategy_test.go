package app

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startStrategyUpstream(t *testing.T, delay time.Duration, answerIP string) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			time.Sleep(delay)
			response := new(dns.Msg)
			response.SetReply(request)
			if len(request.Question) == 1 {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(answerIP).To4(),
				})
			}
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return packetConn.LocalAddr().String()
}

func newStrategyTestServer(mode string, upstreams []string) *DNSServer {
	return &DNSServer{
		config: &Config{UpstreamMode: mode},
		client: &dns.Client{Net: "udp", Timeout: time.Second},
		pool:   NewUpstreamPool(upstreams),
	}
}

func TestLoadBalanceStrategyRotatesUpstreams(t *testing.T) {
	first := startStrategyUpstream(t, 0, "1.1.1.1")
	second := startStrategyUpstream(t, 0, "8.8.8.8")
	server := newStrategyTestServer(upstreamModeLoadBalance, []string{first, second})

	request := newTestRequest("strategy.test.", dns.TypeA)
	_, upstreamOne, err := server.exchange(request)
	if err != nil {
		t.Fatal(err)
	}
	_, upstreamTwo, err := server.exchange(request)
	if err != nil {
		t.Fatal(err)
	}
	if upstreamOne == upstreamTwo {
		t.Fatalf("load balance strategy did not rotate upstreams: %q", upstreamOne)
	}
}

func TestParallelStrategyReturnsFirstValidResponse(t *testing.T) {
	slow := startStrategyUpstream(t, 250*time.Millisecond, "1.1.1.1")
	fast := startStrategyUpstream(t, 15*time.Millisecond, "8.8.8.8")
	server := newStrategyTestServer(upstreamModeParallel, []string{slow, fast})

	started := time.Now()
	response, upstream, err := server.exchange(newTestRequest("parallel.test.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if upstream != fast {
		t.Fatalf("parallel strategy selected %q, want %q", upstream, fast)
	}
	if elapsed := time.Since(started); elapsed >= 150*time.Millisecond {
		t.Fatalf("parallel strategy waited for slow upstream: %s", elapsed)
	}
	if answer := response.Answer[0].(*dns.A).A.String(); answer != "8.8.8.8" {
		t.Fatalf("parallel strategy returned %s, want 8.8.8.8", answer)
	}
}

func TestFastestAddressStrategyUsesProbeResult(t *testing.T) {
	fastDNS := startStrategyUpstream(t, 10*time.Millisecond, "1.1.1.1")
	fastAddress := startStrategyUpstream(t, 45*time.Millisecond, "8.8.8.8")
	server := newStrategyTestServer(upstreamModeFastestAddr, []string{fastDNS, fastAddress})
	server.fastestAddrProbe = func(ip net.IP) (time.Duration, bool) {
		if ip.String() == "8.8.8.8" {
			return 5 * time.Millisecond, true
		}
		return 90 * time.Millisecond, true
	}

	response, upstream, err := server.exchange(newTestRequest("fastest-address.test.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if upstream != fastAddress {
		t.Fatalf("fastest address strategy selected %q, want %q", upstream, fastAddress)
	}
	if answer := response.Answer[0].(*dns.A).A.String(); answer != "8.8.8.8" {
		t.Fatalf("fastest address strategy returned %s, want 8.8.8.8", answer)
	}
}

func TestFallbackUpstreamUsedAfterPrimarySERVFAIL(t *testing.T) {
	primaryConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	primary := &dns.Server{PacketConn: primaryConn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeServerFailure
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = primary.ActivateAndServe() }()
	t.Cleanup(func() { _ = primary.Shutdown() })

	backup := startStrategyUpstream(t, 0, "8.8.4.4")
	server := newStrategyTestServer(upstreamModeLoadBalance, []string{primaryConn.LocalAddr().String()})
	server.config.FallbackUpstreams = []string{backup}
	server.fallbackPool = NewUpstreamPool(server.config.FallbackUpstreams)

	response, upstream, err := server.exchange(newTestRequest("fallback.test.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if upstream != backup {
		t.Fatalf("fallback upstream = %q, want %q", upstream, backup)
	}
	if answer := response.Answer[0].(*dns.A).A.String(); answer != "8.8.4.4" {
		t.Fatalf("fallback answer = %s, want 8.8.4.4", answer)
	}
}

func TestResponseAddressesIgnorePrivateAddresses(t *testing.T) {
	response := new(dns.Msg)
	response.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.168.1.10").To4()},
		&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("1.1.1.1").To4()},
	}
	addresses := responseAddresses(response)
	if len(addresses) != 1 || addresses[0].String() != "1.1.1.1" {
		t.Fatalf("unexpected probeable addresses: %#v", addresses)
	}
}

func TestPrioritizeResponseAddressKeepsRecordGroupsIntact(t *testing.T) {
	response := new(dns.Msg)
	response.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "cdn.example.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("1.1.1.1").To4()},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("8.8.8.8").To4()},
	}
	prioritized := prioritizeResponseAddress(response, net.ParseIP("8.8.8.8"))
	if _, ok := prioritized.Answer[0].(*dns.CNAME); !ok {
		t.Fatal("prioritization moved an address ahead of the CNAME")
	}
	if address := prioritized.Answer[1].(*dns.A).A.String(); address != "8.8.8.8" {
		t.Fatalf("prioritized first address = %s, want 8.8.8.8", address)
	}
}
