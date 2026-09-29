package app

import (
	"os"
	"path/filepath"
	"testing"

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
		pool:   NewUpstreamPool(config.Upstreams),
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
