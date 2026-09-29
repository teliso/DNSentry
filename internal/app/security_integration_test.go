package app

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

type securityCaptureWriter struct {
	response *dns.Msg
	remote   net.Addr
}

func (w *securityCaptureWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *securityCaptureWriter) RemoteAddr() net.Addr { return w.remote }
func (w *securityCaptureWriter) WriteMsg(message *dns.Msg) error {
	w.response = message.Copy()
	return nil
}
func (w *securityCaptureWriter) Write(packet []byte) (int, error) {
	message := new(dns.Msg)
	if err := message.Unpack(packet); err != nil {
		return 0, err
	}
	w.response = message
	return len(packet), nil
}
func (w *securityCaptureWriter) Close() error        { return nil }
func (w *securityCaptureWriter) TsigStatus() error   { return nil }
func (w *securityCaptureWriter) TsigTimersOnly(bool) {}
func (w *securityCaptureWriter) Hijack()             {}

func newSecurityPipelineServer(t *testing.T, config *Config) *DNSServer {
	t.Helper()
	directory := t.TempDir()
	ruleFile := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(ruleFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules := rules.NewStore(ruleFile)
	if err := rules.Reload(); err != nil {
		t.Fatal(err)
	}
	config.RulesFile = ruleFile
	return &DNSServer{
		config: config,
		rules:  rules,
		cache:  cache.New(1<<20, true),
		logs:   querylog.New(100),
		client: &dns.Client{Net: "udp", Timeout: time.Second},
		pool:   NewUpstreamPool(config.Upstreams),
	}
}

func TestDNSAccessControlAppliesToServeDNS(t *testing.T) {
	config := &Config{DNSListens: []string{":15353"}, HTTPListen: "127.0.0.1:18080", CacheEnabled: true, Upstreams: []string{"127.0.0.1:1"}}
	server := newSecurityPipelineServer(t, config)
	server.setLocalRecords([]LocalRecord{{Domain: "router.home", Type: "A", Value: "192.168.1.1", TTL: 60}})
	server.configureAccess(DNSAccessConfig{AllowedClients: []string{"192.0.2.0/24"}})
	request := newTestRequest("router.home.", dns.TypeA)

	denied := &securityCaptureWriter{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 4000}}
	server.ServeDNS(denied, request)
	if denied.response == nil || denied.response.Rcode != dns.RcodeRefused {
		t.Fatalf("denied client response = %#v", denied.response)
	}

	allowed := &securityCaptureWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4000}}
	server.ServeDNS(allowed, request)
	if allowed.response == nil || len(allowed.response.Answer) != 1 || allowed.response.Answer[0].(*dns.A).A.String() != "192.168.1.1" {
		t.Fatalf("allowed client did not receive local answer: %#v", allowed.response)
	}
	stats := server.logs.SecurityStats()
	if stats.DeniedClients != 1 {
		t.Fatalf("denied client metric = %d, want 1", stats.DeniedClients)
	}
}

func TestClientRateLimitAppliesBeforeResolution(t *testing.T) {
	config := &Config{DNSListens: []string{":15353"}, HTTPListen: "127.0.0.1:18080", CacheEnabled: true, Upstreams: []string{"127.0.0.1:1"}}
	server := newSecurityPipelineServer(t, config)
	server.setLocalRecords([]LocalRecord{{Domain: "router.home", Type: "A", Value: "192.168.1.1", TTL: 60}})
	server.configureAccess(DNSAccessConfig{ClientRateLimitQPS: 1})
	request := newTestRequest("router.home.", dns.TypeA)
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4000}

	for attempt := 0; attempt < 2; attempt++ {
		writer := &securityCaptureWriter{remote: remote}
		server.ServeDNS(writer, request)
		if writer.response == nil || writer.response.Rcode != dns.RcodeSuccess {
			t.Fatalf("burst request %d was rejected: %#v", attempt, writer.response)
		}
	}
	limited := &securityCaptureWriter{remote: remote}
	server.ServeDNS(limited, request)
	if limited.response == nil || limited.response.Rcode != dns.RcodeRefused {
		t.Fatalf("rate-limited response = %#v", limited.response)
	}
	if got := server.logs.SecurityStats().RateLimited; got != 1 {
		t.Fatalf("rate-limited metric = %d, want 1", got)
	}
}

func TestRebindingProtectionAppliesToUpstreamResponse(t *testing.T) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: connection, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 168, 1, 10)}}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })

	config := &Config{DNSListens: []string{":15353"}, HTTPListen: "127.0.0.1:18080", CacheEnabled: true, Upstreams: []string{connection.LocalAddr().String()}}
	server := newSecurityPipelineServer(t, config)
	server.configureAccess(DNSAccessConfig{RebindingProtection: true})
	writer := &securityCaptureWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4000}}
	server.ServeDNS(writer, newTestRequest("public.example.", dns.TypeA))
	if writer.response == nil || writer.response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rebinding response = %#v", writer.response)
	}
	if got := server.logs.SecurityStats().RebindingBlocked; got != 1 {
		t.Fatalf("rebinding metric = %d, want 1", got)
	}
}
