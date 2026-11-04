package app

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
	"github.com/teliso/DNSentry/internal/services"
	"github.com/teliso/DNSentry/internal/upstream"
)

func newFilterTestServer(t *testing.T, ruleText string, mutate func(*Config)) (*DNSServer, *atomic.Int32) {
	t.Helper()
	file := t.TempDir() + "/rules.txt"
	if err := os.WriteFile(file, []byte(ruleText), 0600); err != nil {
		t.Fatal(err)
	}
	store := rules.NewStore(file)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	address, count := startAnswerServer(t, net.IPv4(203, 0, 113, 9))
	config := &Config{Upstreams: []string{address}, BlockingMode: "nxdomain", CacheSize: 1 << 20}
	if mutate != nil {
		mutate(config)
	}
	server := &DNSServer{
		config: config, rules: store, cache: cache.New(config.CacheSize, false), logs: querylog.New(20),
		client: &dns.Client{Net: "udp", Timeout: time.Second}, pool: upstream.NewPool(config.Upstreams), dnssecCacheOK: map[string]struct{}{},
	}
	server.blockedServices.Store(services.NewMatcher(config.BlockedServices))
	return server, count
}

func ask(server *DNSServer, name string, qtype uint16) *dns.Msg {
	writer := new(captureResponseWriter)
	server.ServeDNS(writer, newTestRequest(name, qtype))
	return writer.response
}

func TestBlockedServiceBlocksItsDomainsUnlessAllowed(t *testing.T) {
	server, count := newFilterTestServer(t, "@@||allowed.tiktok.com^\n", func(c *Config) { c.BlockedServices = []string{"tiktok"} })
	if response := ask(server, "v16.tiktokcdn.com.", dns.TypeA); response == nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked service subdomain: %v", response)
	}
	if list := server.logs.List(); len(list) != 1 || list[0].Action != "block" || list[0].Rule != "服务：TikTok" {
		t.Fatalf("log entry = %#v", list)
	}
	if response := ask(server, "allowed.tiktok.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("an allow rule must override a blocked service: %v", response)
	}
	if response := ask(server, "example.org.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("unrelated domain: %v", response)
	}
	if count.Load() != 2 {
		t.Fatalf("blocked queries must not reach the upstream, upstream saw %d", count.Load())
	}
	server.pauseProtection(time.Hour)
	if response := ask(server, "www.tiktok.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("paused protection must not block services: %v", response)
	}
}

func TestSafeSearchRewritesSearchEnginesToTheirFilteredHosts(t *testing.T) {
	server, _ := newFilterTestServer(t, "", func(c *Config) { c.SafeSearch = true })
	response := ask(server, "www.google.com.", dns.TypeA)
	if response == nil || len(response.Answer) != 2 {
		t.Fatalf("response = %v", response)
	}
	cname, ok := response.Answer[0].(*dns.CNAME)
	if !ok || cname.Target != "forcesafesearch.google.com." || cname.Hdr.Name != "www.google.com." {
		t.Fatalf("first answer = %v", response.Answer[0])
	}
	if a, ok := response.Answer[1].(*dns.A); !ok || a.A.String() != "203.0.113.9" {
		t.Fatalf("second answer = %v", response.Answer[1])
	}
	if entries := server.logs.List(); entries[0].Rule != "安全搜索 → forcesafesearch.google.com" {
		t.Fatalf("log rule = %q", entries[0].Rule)
	}
	if response := ask(server, "www.google.com.", dns.TypeHTTPS); response == nil || len(response.Answer) != 0 || response.Rcode != dns.RcodeSuccess {
		t.Fatalf("HTTPS records must be answered empty: %v", response)
	}
	if response := ask(server, "mail.google.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("other hosts must resolve normally: %v", response)
	}

	off, _ := newFilterTestServer(t, "", nil)
	if response := ask(off, "www.google.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("safe search off must not redirect: %v", response)
	}
}

func TestBlockedServicesAreValidated(t *testing.T) {
	config := testConfig()
	config.BlockedServices = []string{"youtube", "tiktok", "youtube"}
	validated, err := validateConfig(config)
	if err != nil || len(validated.BlockedServices) != 2 || validated.BlockedServices[0] != "tiktok" {
		t.Fatalf("validated = %v, %v", validated.BlockedServices, err)
	}
	config = testConfig()
	config.BlockedServices = []string{"no-such-service"}
	if _, err := validateConfig(config); err == nil {
		t.Fatal("an unknown service was accepted")
	}
}
