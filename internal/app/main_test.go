package app

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/vigordns/vigordns/internal/cache"
)

func TestBlockingModes(t *testing.T) {
	request := newTestRequest("blocked.test.", dns.TypeA)
	config := &Config{BlockingMode: "nxdomain", BlockingIPv4: "0.0.0.0", BlockingIPv6: "::", BlockedResponseTTL: 10}
	if response := blockedResponse(request, request.Question[0], config); response.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN response, got %d", response.Rcode)
	}
	config.BlockingMode = "null_ip"
	response := blockedResponse(request, request.Question[0], config)
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatalf("expected null IPv4 response, got %v", response)
	}
	config.BlockingMode = "custom_ip"
	config.BlockingIPv4 = "192.0.2.15"
	response = blockedResponse(request, request.Question[0], config)
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.15" {
		t.Fatalf("expected custom IPv4 response, got %v", response)
	}
	config.BlockingMode = "default"
	response = blockedResponse(request, request.Question[0], config)
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatalf("expected default IPv4 response, got %v", response)
	}
	config.BlockingMode = "refused"
	response = blockedResponse(request, request.Question[0], config)
	if response.Rcode != dns.RcodeRefused || len(response.Answer) != 0 {
		t.Fatalf("expected REFUSED response, got %v", response)
	}
}

func TestRewriteResponse(t *testing.T) {
	request := newTestRequest("home.lan.", 1)
	response := rewriteResponse(request, request.Question[0], net.ParseIP("192.168.1.10"))
	if response == nil || len(response.Answer) != 1 {
		t.Fatal("expected one rewrite answer")
	}
	if got := response.Answer[0].String(); got == "" {
		t.Fatal("expected a serialized rewrite answer")
	}
}

func TestCacheResponsePolicies(t *testing.T) {
	message := newTestRequest("ttl.test.", dns.TypeA)
	message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ttl.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.IPv4(192, 0, 2, 2)}}
	config := &Config{CacheTTLMin: 30}
	cached, ttl, ok := prepareCacheResponse(message, config)
	if !ok || ttl != 30 || cached.Answer[0].Header().Ttl != 30 {
		t.Fatalf("expected minimum TTL to apply to response, got ok=%v ttl=%d answer=%d", ok, ttl, cached.Answer[0].Header().Ttl)
	}

	message.Answer[0].Header().Ttl = 0
	cached, ttl, ok = prepareCacheResponse(message, &Config{CacheTTLMin: 30})
	if !ok || ttl != 30 || cached.Answer[0].Header().Ttl != 30 {
		t.Fatalf("expected minimum TTL to make zero-TTL response cacheable, got ok=%v ttl=%d answer=%d", ok, ttl, cached.Answer[0].Header().Ttl)
	}

	message.Answer[0].Header().Ttl = 200000
	cached, ttl, ok = prepareCacheResponse(message, &Config{})
	if !ok || ttl != 200000 || cached.Answer[0].Header().Ttl != 200000 {
		t.Fatalf("expected zero maximum TTL to mean unlimited, got ok=%v ttl=%d answer=%d", ok, ttl, cached.Answer[0].Header().Ttl)
	}
}

func TestResponseTTLKeepsZeroTTLRecords(t *testing.T) {
	message := newTestRequest("ttl.test.", dns.TypeA)
	message.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ttl.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(192, 0, 2, 3)},
		&dns.A{Hdr: dns.RR_Header{Name: "ttl.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20}, A: net.IPv4(192, 0, 2, 4)},
	}
	if got := responseTTL(message); got != 0 {
		t.Fatalf("expected zero TTL to be the response TTL, got %d", got)
	}
}

func TestCacheKeySeparatesDNSSECRequests(t *testing.T) {
	request := newTestRequest("Example.COM.", dns.TypeA)
	plainKey, ok := makeCacheKey(request)
	if !ok {
		t.Fatal("expected ordinary request to be cacheable")
	}
	dnssecRequest := request.Copy()
	dnssecRequest.SetEdns0(1232, true)
	dnssecKey, ok := makeCacheKey(dnssecRequest)
	if !ok || plainKey == dnssecKey {
		t.Fatalf("expected DO bit to separate cache keys: %q %q", plainKey, dnssecKey)
	}

	ecsRequest := request.Copy()
	ecsRequest.SetEdns0(1232, false)
	ecsRequest.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)}}
	ecsKey, ok := makeCacheKey(ecsRequest)
	if !ok || ecsKey == plainKey {
		t.Fatalf("expected ECS subnet to create a cache variant: %q %q", plainKey, ecsKey)
	}

	optionRequest := request.Copy()
	optionRequest.SetEdns0(1232, false)
	optionRequest.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{}}
	if key, ok := makeCacheKey(optionRequest); ok || key != "" {
		t.Fatalf("expected unsupported EDNS options to bypass cache, got key=%q ok=%v", key, ok)
	}
}

func TestUncacheableResponses(t *testing.T) {
	message := newTestRequest("failure.test.", dns.TypeA)
	message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "failure.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 5)}}
	for _, rcode := range []int{dns.RcodeRefused, dns.RcodeNotImplemented} {
		message.Rcode = rcode
		if isCacheableResponse(message) {
			t.Fatalf("rcode %d should not be cached", rcode)
		}
	}
	message.Rcode = dns.RcodeSuccess
	message.Truncated = true
	if isCacheableResponse(message) {
		t.Fatal("truncated response should not be cached")
	}
}

func TestSERVFAILUsesShortCacheTTL(t *testing.T) {
	message := newTestRequest("failure.test.", dns.TypeA)
	message.Rcode = dns.RcodeServerFailure
	cached, ttl, ok := prepareCacheResponse(message, &Config{})
	if !ok || ttl != cache.ServfailTTL || cached.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL cache TTL %d, got ok=%v ttl=%d", cache.ServfailTTL, ok, ttl)
	}
}

func TestCacheableNegativeResponses(t *testing.T) {
	message := newTestRequest("missing.test.", dns.TypeA)
	message.Rcode = dns.RcodeNameError
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}}}
	if !isCacheableResponse(message) {
		t.Fatal("expected NXDOMAIN with SOA to be cacheable")
	}
	message.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}}}
	if isCacheableResponse(message) {
		t.Fatal("referral without SOA should not be cacheable")
	}
	message.Rcode = dns.RcodeSuccess
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}}}
	if !isCacheableResponse(message) {
		t.Fatal("expected NODATA with SOA to be cacheable")
	}
}

func TestCNAMEOnlyAddressResponseIsNotCacheable(t *testing.T) {
	message := newTestRequest("alias.test.", dns.TypeA)
	message.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.test."}}
	if isCacheableResponse(message) {
		t.Fatal("A response with only CNAME should not be cached")
	}
}

func TestCachedResponseIsFilteredForClient(t *testing.T) {
	message := newTestRequest("secure.test.", dns.TypeA)
	message.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "secure.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 9)},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "secure.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}},
	}
	message.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}}
	message.AuthenticatedData = true
	filtered := filterCachedResponse(message, newTestRequest("secure.test.", dns.TypeA))
	if len(filtered.Answer) != 1 || filtered.Answer[0].Header().Rrtype != dns.TypeA || len(filtered.Extra) != 0 || filtered.AuthenticatedData {
		t.Fatalf("expected unvalidated AD and DNSSEC/OPT records to be filtered: %#v", filtered)
	}
}

func TestCacheResponseGuards(t *testing.T) {
	message := newTestRequest("transfer.test.", dns.TypeA)
	message.Question[0].Qtype = dns.TypeAXFR
	if key, ok := makeCacheKey(message); ok || key != "" {
		t.Fatalf("expected AXFR to bypass cache, got key=%q ok=%v", key, ok)
	}
	message.Question[0].Qtype = dns.TypeA
	message.Opcode = dns.OpcodeNotify
	if isCacheableResponse(message) {
		t.Fatal("non-query response should not be cacheable")
	}
}

func TestNegativeCacheTTLUsesSOAMinimum(t *testing.T) {
	message := newTestRequest("missing.test.", dns.TypeA)
	message.Rcode = dns.RcodeNameError
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600}, Minttl: 30}}
	if got := cacheResponseTTL(message); got != 30 {
		t.Fatalf("expected negative cache TTL 30, got %d", got)
	}
}

func TestValidateUpstreamResponse(t *testing.T) {
	request := newTestRequest("Example.COM.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)

	tests := []struct {
		name   string
		mutate func(*dns.Msg)
	}{
		{
			name: "ID",
			mutate: func(message *dns.Msg) {
				message.Id++
			},
		},
		{
			name: "QNAME",
			mutate: func(message *dns.Msg) {
				message.Question[0].Name = "other.example."
			},
		},
		{
			name: "QTYPE",
			mutate: func(message *dns.Msg) {
				message.Question[0].Qtype = dns.TypeAAAA
			},
		},
		{
			name: "QCLASS",
			mutate: func(message *dns.Msg) {
				message.Question[0].Qclass = dns.ClassCHAOS
			},
		},
		{
			name: "QR",
			mutate: func(message *dns.Msg) {
				message.Response = false
			},
		},
		{
			name: "Opcode",
			mutate: func(message *dns.Msg) {
				message.Opcode = dns.OpcodeStatus
			},
		},
		{
			name: "multiple questions",
			mutate: func(message *dns.Msg) {
				message.Question = append(message.Question, message.Question[0])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := response.Copy()
			test.mutate(invalid)
			if err := validateUpstreamResponse(request, invalid); err == nil {
				t.Fatalf("expected invalid %s response to be rejected", test.name)
			}
		})
	}

	doqRequest := request.Copy()
	doqRequest.Id = 0
	doqResponse := response.Copy()
	doqResponse.Id = 0
	if err := validateUpstreamResponse(doqRequest, doqResponse); err != nil {
		t.Fatalf("expected DoQ response with zero ID to be accepted: %v", err)
	}
}

func TestRetryableUpstreamRCodes(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		message := newTestRequest("upstream.test.", dns.TypeA)
		message.Rcode = rcode
		if !shouldRetryUpstreamResponse(message) {
			t.Fatalf("expected RCODE %d to be retryable", rcode)
		}
	}
	message := newTestRequest("upstream.test.", dns.TypeA)
	if shouldRetryUpstreamResponse(message) {
		t.Fatal("successful response should not be retryable")
	}
}

func TestDoHClientCacheSharesOriginAndIsolatesOthers(t *testing.T) {
	server := &DNSServer{client: &dns.Client{Timeout: time.Second}}
	defer func() {
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	firstURL, err := url.Parse("https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	first, err := server.acquireDoHClient(dohOrigin(firstURL, "443"), firstURL.Hostname(), "443")
	if err != nil {
		t.Fatal(err)
	}

	secondURL, err := url.Parse("https://DNS.EXAMPLE/alternate")
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.acquireDoHClient(dohOrigin(secondURL, "443"), secondURL.Hostname(), "443")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.client != second.client || first.transport != second.transport {
		t.Fatal("expected the same origin to reuse its DoH client and transport")
	}
	if first.transport.MaxIdleConns != dohMaxIdleConns || first.transport.MaxIdleConnsPerHost != dohMaxIdleConnsPerHost || first.transport.IdleConnTimeout != dohIdleConnTimeout {
		t.Fatalf("unexpected DoH transport pool settings: max_idle=%d per_host=%d idle_timeout=%s", first.transport.MaxIdleConns, first.transport.MaxIdleConnsPerHost, first.transport.IdleConnTimeout)
	}

	otherURL, err := url.Parse("https://dns.example:8443/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	other, err := server.acquireDoHClient(dohOrigin(otherURL, "8443"), otherURL.Hostname(), "8443")
	if err != nil {
		t.Fatal(err)
	}
	if other == first || other.client == first.client || other.transport == first.transport {
		t.Fatal("expected different origins to use isolated DoH clients and transports")
	}

	server.releaseDoHClient(first)
	server.releaseDoHClient(second)
	server.releaseDoHClient(other)
	if len(server.dohClients) != 2 {
		t.Fatalf("expected two cached origins, got %d", len(server.dohClients))
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if len(server.dohClients) != 0 {
		t.Fatalf("expected Close to clear cached DoH clients, got %d", len(server.dohClients))
	}
	if _, err := server.acquireDoHClient(originForTest(firstURL), firstURL.Hostname(), "443"); err == nil {
		t.Fatal("expected acquiring a DoH client after Close to fail")
	}
}

func originForTest(endpoint *url.URL) string {
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	return dohOrigin(endpoint, port)
}

func TestDoHClientCacheIsInvalidatedOnConfigUpdate(t *testing.T) {
	server := &DNSServer{
		config: &Config{},
		client: &dns.Client{Timeout: time.Second},
	}
	defer server.Close()

	endpoint, err := url.Parse("https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	origin := dohOrigin(endpoint, "443")
	old, err := server.acquireDoHClient(origin, endpoint.Hostname(), "443")
	if err != nil {
		t.Fatal(err)
	}
	server.releaseDoHClient(old)

	server.updateConfig(Config{})
	if len(server.dohClients) != 0 {
		t.Fatalf("expected config update to clear DoH clients, got %d", len(server.dohClients))
	}
	fresh, err := server.acquireDoHClient(origin, endpoint.Hostname(), "443")
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || fresh.client == old.client || fresh.transport == old.transport {
		t.Fatal("expected config update to replace the old DoH client and transport")
	}
	server.releaseDoHClient(fresh)
}

func newTestRequest(name string, qtype uint16) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Id: 1, RecursionDesired: true}, Question: []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}}
}
