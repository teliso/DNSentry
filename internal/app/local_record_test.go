package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teliso/DNSentry/internal/upstream"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

func TestLocalRecordsAreValidatedAndServedBeforeUpstream(t *testing.T) {
	tests := []LocalRecord{
		{Domain: "router.home", Type: "A", Value: "192.168.1.1", TTL: 60},
		{Domain: "alias.home", Type: "CNAME", Value: "router.home", TTL: 60},
		{Domain: "txt.home", Type: "TXT", Value: "managed by DNSentry", TTL: 60},
	}
	if err := validateLocalRecords(tests); err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	ruleFile := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(ruleFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules := rules.NewStore(ruleFile)
	if err := rules.Reload(); err != nil {
		t.Fatal(err)
	}
	config := &Config{
		DNSListens:   []string{":15353"},
		HTTPListen:   "127.0.0.1:18080",
		RulesFile:    ruleFile,
		CacheEnabled: true,
		CacheSize:    1 << 20,
		LocalRecords: tests,
		Upstreams:    []string{"127.0.0.1:1"},
	}
	server := &DNSServer{
		config: config,
		rules:  rules,
		cache:  cache.New(config.CacheSize, true),
		logs:   querylog.New(10),
		client: &dns.Client{Net: "udp"},
		pool:   upstream.NewPool(config.Upstreams),
	}
	server.setLocalRecords(config.LocalRecords)

	request := newTestRequest("router.home.", dns.TypeA)
	writer := new(captureResponseWriter)
	server.ServeDNS(writer, request)
	if writer.response == nil || len(writer.response.Answer) != 1 {
		t.Fatalf("local record response missing: %#v", writer.response)
	}
	answer, ok := writer.response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != "192.168.1.1" || !writer.response.Authoritative {
		t.Fatalf("unexpected local record response: %#v", writer.response)
	}
	if stats := server.cache.Stats(); stats.Misses != 0 {
		t.Fatalf("local record lookup should not touch cache: %#v", stats)
	}
}

func TestLocalRecordValidationRejectsInvalidValues(t *testing.T) {
	for _, record := range []LocalRecord{
		{Domain: "router.home", Type: "A", Value: "not-an-ip"},
		{Domain: "router.home", Type: "AAAA", Value: "192.0.2.1"},
		{Domain: "router.home", Type: "CNAME", Value: "not a domain"},
		{Domain: "router.home", Type: "MX", Value: "mail.home"},
	} {
		if err := validateLocalRecords([]LocalRecord{record}); err == nil {
			t.Fatalf("invalid local record was accepted: %#v", record)
		}
	}
}

func wildcardServer(t *testing.T, records []LocalRecord) *DNSServer {
	t.Helper()
	if err := validateLocalRecords(records); err != nil {
		t.Fatal(err)
	}
	server := &DNSServer{config: &Config{Upstreams: []string{"127.0.0.1:1"}}, cache: cache.New(1<<20, false), logs: querylog.New(10), client: &dns.Client{Net: "udp", Timeout: time.Second}, pool: upstream.NewPool([]string{"127.0.0.1:1"}), rules: rules.NewStore(filepath.Join(t.TempDir(), "r.txt"))}
	server.setLocalRecords(records)
	return server
}

func TestWildcardLocalRecords(t *testing.T) {
	server := wildcardServer(t, []LocalRecord{
		{Domain: "*.nas.home", Type: "A", Value: "192.168.1.10"},
		{Domain: "special.nas.home", Type: "A", Value: "192.168.1.11"},
		{Domain: "*.deep.nas.home", Type: "A", Value: "192.168.1.12"},
		{Domain: "alias.home", Type: "CNAME", Value: "host.home"},
		{Domain: "host.home", Type: "A", Value: "192.168.1.20"},
		{Domain: "*.apps.home", Type: "CNAME", Value: "host.home"},
	})
	address := func(name string, qtype uint16) (rcode int, answers []dns.RR) {
		response := ask(server, name, qtype)
		if response == nil {
			t.Fatalf("no response for %s", name)
		}
		return response.Rcode, response.Answer
	}
	for name, want := range map[string]string{
		"a.nas.home.":       "192.168.1.10", // wildcard
		"x.y.nas.home.":     "192.168.1.10", // several labels below the wildcard
		"SPECIAL.nas.home.": "192.168.1.11", // an exact record wins
		"a.deep.nas.home.":  "192.168.1.12", // the closest wildcard wins
		"alias.home.":       "192.168.1.20", // A query for a local CNAME is followed
		"photos.apps.home.": "192.168.1.20", // wildcard CNAME, followed
	} {
		_, answers := address(name, dns.TypeA)
		var got string
		for _, answer := range answers {
			if a, ok := answer.(*dns.A); ok {
				got = a.A.String()
				if !strings.EqualFold(a.Hdr.Name, "host.home.") && !strings.EqualFold(a.Hdr.Name, dns.Fqdn(name)) {
					t.Errorf("%s: answer owner %q", name, a.Hdr.Name)
				}
			}
		}
		if got != want {
			t.Errorf("%s = %q (%v), want %s", name, got, answers, want)
		}
	}
	if _, answers := address("photos.apps.home.", dns.TypeA); len(answers) < 1 || answers[0].Header().Name != "photos.apps.home." || answers[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("the wildcard CNAME must be owned by the asked name: %v", answers)
	}
	// The wildcard name itself is not covered (nas.home is not below *.nas.home), and an existing name
	// does not fall back to the wildcard for a type it lacks (checked against the snapshot, no upstream).
	snapshot := server.localRecords.Load()
	if len(snapshot.lookup("nas.home", "A")) != 0 {
		t.Error("*.nas.home must not match nas.home")
	}
	if len(snapshot.lookup("special.nas.home", "TXT")) != 0 {
		t.Error("an existing name must not be answered from a wildcard")
	}
	// No reverse record is derived from a wildcard.
	if len(snapshot.ptr) != 2 {
		t.Errorf("PTR records = %d, want 2 (special and host; wildcards derive none)", len(snapshot.ptr))
	}
}

func TestWildcardNameValidation(t *testing.T) {
	for _, domain := range []string{"*.home", "*.a.b.home"} {
		if err := validateLocalRecords([]LocalRecord{{Domain: domain, Type: "A", Value: "192.0.2.1"}}); err != nil {
			t.Errorf("%s rejected: %v", domain, err)
		}
	}
	for _, domain := range []string{"*", "*.", "a.*.home", "**.home", "*home", "*.*.home"} {
		if err := validateLocalRecords([]LocalRecord{{Domain: domain, Type: "A", Value: "192.0.2.1"}}); err == nil {
			t.Errorf("%q was accepted", domain)
		}
	}
}
