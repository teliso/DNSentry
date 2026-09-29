package app

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClientAccessPolicyHonorsAllowAndDeny(t *testing.T) {
	policy := newClientAccessPolicy(DNSAccessConfig{
		AllowedClients: []string{"192.0.2.0/24"},
		DeniedClients:  []string{"192.0.2.10"},
	})
	if !policy.allows("192.0.2.11") {
		t.Fatal("allowed client was denied")
	}
	if policy.allows("192.0.2.10") {
		t.Fatal("denied client was allowed")
	}
	if policy.allows("198.51.100.1") {
		t.Fatal("client outside allowlist was allowed")
	}
}

func TestClientRateLimiterEnforcesQPS(t *testing.T) {
	limiter := newClientRateLimiter(1)
	if !limiter.Allow("192.0.2.1") {
		t.Fatal("initial burst should allow the first request")
	}
	if !limiter.Allow("192.0.2.1") {
		t.Fatal("initial burst should allow two requests")
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatal("rate limiter allowed a request beyond the burst")
	}
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow("192.0.2.1") {
		t.Fatal("rate limiter did not refill a token")
	}
}

func TestRebindingProtectionBlocksPrivateAnswers(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "public.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 168, 1, 10)}}
	question := dns.Question{Name: "public.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	policy := newClientAccessPolicy(DNSAccessConfig{RebindingProtection: true})
	filtered, blocked := filterRebindingResponse(response, question, policy)
	if !blocked || filtered.Rcode != dns.RcodeServerFailure || len(filtered.Answer) != 0 {
		t.Fatalf("private answer was not blocked: blocked=%v response=%#v", blocked, filtered)
	}
}

func TestRebindingProtectionAllowsConfiguredDomain(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "nas.home.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 168, 1, 10)}}
	question := dns.Question{Name: "nas.home.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	policy := newClientAccessPolicy(DNSAccessConfig{RebindingProtection: true, RebindingAllowDomains: []string{"home"}})
	filtered, blocked := filterRebindingResponse(response, question, policy)
	if blocked || filtered != response {
		t.Fatalf("configured private domain was blocked")
	}
}
