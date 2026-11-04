package app

import (
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
	"github.com/teliso/DNSentry/internal/schedule"
	"github.com/teliso/DNSentry/internal/services"
	"github.com/teliso/DNSentry/internal/upstream"
	"gopkg.in/yaml.v3"
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

func TestBlockedResponsesCarryExtendedErrorsAndNegativeCaching(t *testing.T) {
	server, _ := newFilterTestServer(t, "||ads.test^\n", func(c *Config) { c.BlockedServices = []string{"tiktok"}; c.BlockingMode = "null_ip" })
	ede := func(response *dns.Msg) *dns.EDNS0_EDE {
		if opt := response.IsEdns0(); opt != nil {
			for _, option := range opt.Option {
				if e, ok := option.(*dns.EDNS0_EDE); ok {
					return e
				}
			}
		}
		return nil
	}
	query := func(name string, qtype uint16, edns bool) *dns.Msg {
		request := newTestRequest(name, qtype)
		if edns {
			request.SetEdns0(1232, false)
		}
		writer := new(captureResponseWriter)
		server.ServeDNS(writer, request)
		return writer.response
	}

	if e := ede(query("ads.test.", dns.TypeA, true)); e == nil || e.InfoCode != dns.ExtendedErrorCodeBlocked {
		t.Fatalf("a filter rule must report EDE Blocked, got %v", e)
	}
	if e := ede(query("www.tiktok.com.", dns.TypeA, true)); e == nil || e.InfoCode != dns.ExtendedErrorCodeFiltered || !strings.Contains(e.ExtraText, "TikTok") {
		t.Fatalf("a blocked service must report EDE Filtered naming it, got %v", e)
	}
	plain := query("ads.test.", dns.TypeA, false)
	if plain.IsEdns0() != nil || len(plain.Answer) != 1 {
		t.Fatalf("a client without EDNS must not receive OPT: %v", plain)
	}
	// Other types get an empty NOERROR answer with an SOA, so it can be cached.
	https := query("ads.test.", dns.TypeHTTPS, true)
	if https.Rcode != dns.RcodeSuccess || len(https.Answer) != 0 || len(https.Ns) != 1 || https.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("HTTPS for a blocked name = %v", https)
	}
	if soa := https.Ns[0].(*dns.SOA); soa.Minttl != 10 || soa.Hdr.Ttl != 10 {
		t.Fatalf("negative cache time = %d/%d", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestScheduledWindowsBlockServicesAndForceSafeSearch(t *testing.T) {
	always := schedule.Config{Timezone: "UTC", Rules: []schedule.Rule{{Name: "family", Enabled: true, Start: "00:00", End: "00:00", Services: []string{"tiktok"}, SafeSearch: true}}}
	if err := schedule.Normalize(&always); err != nil {
		t.Fatal(err)
	}
	server, _ := newFilterTestServer(t, "@@||allowed.tiktok.com^\n", nil)
	server.schedules.Store(schedule.Compile(always))

	if response := ask(server, "www.tiktok.com.", dns.TypeA); response == nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("a scheduled service must be blocked inside its window: %v", response)
	}
	if list := server.logs.List(); list[0].Rule != "计划「family」：TikTok" || list[0].Action != "block" {
		t.Fatalf("log entry = %#v", list[0])
	}
	if response := ask(server, "allowed.tiktok.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("an allow rule must beat a schedule: %v", response)
	}
	if response := ask(server, "www.google.com.", dns.TypeA); response == nil || len(response.Answer) != 2 {
		t.Fatalf("a schedule must be able to force safe search: %v", response)
	}
	if names := activeSchedules(server); len(names) != 1 || names[0] != "family" {
		t.Fatalf("active = %v", names)
	}

	// Outside the window (here: disabled) nothing applies.
	off := always
	off.Rules = []schedule.Rule{{Name: "family", Enabled: false, Start: "00:00", End: "00:00", Services: []string{"tiktok"}}}
	server.schedules.Store(schedule.Compile(off))
	if response := ask(server, "www.tiktok.com.", dns.TypeA); response == nil || len(response.Answer) != 1 {
		t.Fatalf("a closed window must not block: %v", response)
	}
	if names := activeSchedules(server); names == nil || len(names) != 0 {
		t.Fatalf("active = %#v, want an empty list", names)
	}
}

func TestScheduleIsValidatedWithTheConfiguration(t *testing.T) {
	config := testConfig()
	config.Schedule = schedule.Config{Rules: []schedule.Rule{{Enabled: true, Start: "25:00", End: "07:00", Services: []string{"steam"}}}}
	if _, err := validateConfig(config); err == nil {
		t.Fatal("an invalid schedule was accepted")
	}
	config = testConfig()
	config.Schedule = schedule.Config{Timezone: "Asia/Shanghai", Rules: []schedule.Rule{{Name: " games ", Enabled: true, Days: []int{5, 6}, Start: "22:00", End: "07:00", Services: []string{"steam"}}}}
	validated, err := validateConfig(config)
	if err != nil || validated.Schedule.Rules[0].Name != "games" {
		t.Fatalf("validated = %+v %v", validated.Schedule, err)
	}
	data, _ := yaml.Marshal(newYAMLConfig(validated))
	if !strings.Contains(string(data), "schedule:") || !strings.Contains(string(data), "Asia/Shanghai") {
		t.Fatalf("schedule not written:\n%s", data)
	}
	if data, _ := yaml.Marshal(newYAMLConfig(testConfig())); strings.Contains(string(data), "schedule") {
		t.Fatal("an unused schedule must not be written")
	}
}
