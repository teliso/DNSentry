package app

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestPrepareCacheResponseForIPv4ECSScopes(t *testing.T) {
	request := ecsScopeRequest("192.0.2.123", 1, 24)
	response := ecsScopeResponse(request, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   16,
		Address:       net.ParseIP("192.0.2.0"),
	})

	cached, _, ok := prepareCacheResponseForRequest(request, response, &Config{})
	if !ok {
		t.Fatal("expected IPv4 ECS response to be cacheable")
	}
	got, ok := singleECSOption(cached)
	if !ok || !got.Address.Equal(net.ParseIP("192.0.2.0")) || got.SourceNetmask != 24 || got.SourceScope != 16 {
		t.Fatalf("unexpected cached IPv4 ECS: %#v", got)
	}
}

func TestPrepareCacheResponseForIPv6ECSScopes(t *testing.T) {
	request := ecsScopeRequest("2001:db8:1234:5678::42", 2, 64)
	response := ecsScopeResponse(request, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        2,
		SourceNetmask: 64,
		SourceScope:   48,
		Address:       net.ParseIP("2001:db8:1234::"),
	})

	cached, _, ok := prepareCacheResponseForRequest(request, response, &Config{})
	if !ok {
		t.Fatal("expected IPv6 ECS response to be cacheable")
	}
	got, ok := singleECSOption(cached)
	if !ok || !got.Address.Equal(net.ParseIP("2001:db8:1234::")) || got.SourceNetmask != 64 || got.SourceScope != 48 {
		t.Fatalf("unexpected cached IPv6 ECS: %#v", got)
	}
}

func TestPrepareCacheResponseRejectsInvalidECSScopes(t *testing.T) {
	tests := []struct {
		name     string
		request  *dns.Msg
		response *dns.Msg
	}{
		{
			name:     "IPv4 missing ECS",
			request:  ecsScopeRequest("192.0.2.123", 1, 24),
			response: ecsScopeResponseWithoutECS(ecsScopeRequest("192.0.2.123", 1, 24)),
		},
		{
			name:    "IPv4 duplicate ECS",
			request: ecsScopeRequest("192.0.2.123", 1, 24),
			response: ecsScopeResponseWithOptions(ecsScopeRequest("192.0.2.123", 1, 24),
				&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 16, Address: net.ParseIP("192.0.2.0")},
				&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 16, Address: net.ParseIP("192.0.2.0")}),
		},
		{
			name:    "IPv6 family mismatch",
			request: ecsScopeRequest("2001:db8:1234:5678::42", 2, 64),
			response: ecsScopeResponse(ecsScopeRequest("2001:db8:1234:5678::42", 2, 64), &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 64, SourceScope: 48, Address: net.ParseIP("2001:db8:1234::"),
			}),
		},
		{
			name:    "IPv4 source mismatch",
			request: ecsScopeRequest("192.0.2.123", 1, 24),
			response: ecsScopeResponse(ecsScopeRequest("192.0.2.123", 1, 24), &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 25, SourceScope: 16, Address: net.ParseIP("192.0.2.0"),
			}),
		},
		{
			name:    "IPv6 scope broader than source",
			request: ecsScopeRequest("2001:db8:1234:5678::42", 2, 64),
			response: ecsScopeResponse(ecsScopeRequest("2001:db8:1234:5678::42", 2, 64), &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 64, SourceScope: 65, Address: net.ParseIP("2001:db8:1234:5678::"),
			}),
		},
		{
			name:    "IPv4 scope does not cover request",
			request: ecsScopeRequest("192.0.2.123", 1, 24),
			response: ecsScopeResponse(ecsScopeRequest("192.0.2.123", 1, 24), &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 16, Address: net.ParseIP("198.51.100.0"),
			}),
		},
		{
			name:    "IPv6 host bits not normalized",
			request: ecsScopeRequest("2001:db8:1234:5678::42", 2, 64),
			response: ecsScopeResponse(ecsScopeRequest("2001:db8:1234:5678::42", 2, 64), &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 64, SourceScope: 48, Address: net.ParseIP("2001:db8:1234:5678::1"),
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cached, ttl, ok := prepareCacheResponseForRequest(test.request, test.response, &Config{})
			if ok || ttl != 0 || cached != test.response {
				t.Fatalf("expected ECS response not to be cached, got ok=%v ttl=%d same=%v", ok, ttl, cached == test.response)
			}
		})
	}
}

func TestCachedECSResponseUsesCurrentRequestSource(t *testing.T) {
	request := ecsScopeRequest("192.0.2.123", 1, 24)
	response := ecsScopeResponse(request, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   16,
		Address:       net.ParseIP("192.0.2.0"),
	})
	cached, _, ok := prepareCacheResponseForRequest(request, response, &Config{})
	if !ok {
		t.Fatal("expected response to be cached")
	}

	currentRequest := ecsScopeRequest("192.0.2.200", 1, 24)
	filtered := filterCachedResponse(cached.Copy(), currentRequest)
	got, ok := singleECSOption(filtered)
	if !ok || !got.Address.Equal(net.ParseIP("192.0.2.0")) || got.SourceScope != 16 {
		t.Fatalf("cached ECS leaked or changed scope: %#v", got)
	}
}

func ecsScopeRequest(address string, family uint16, source uint8) *dns.Msg {
	request := newTestRequest("ecs-scope.test.", dns.TypeA)
	request.SetEdns0(1232, false)
	request.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: source, Address: net.ParseIP(address),
	}}
	return request
}

func ecsScopeResponse(request *dns.Msg, subnet *dns.EDNS0_SUBNET) *dns.Msg {
	return ecsScopeResponseWithOptions(request, subnet)
}

func ecsScopeResponseWithoutECS(request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	return response
}

func ecsScopeResponseWithOptions(request *dns.Msg, options ...*dns.EDNS0_SUBNET) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	response.SetEdns0(1232, false)
	response.IsEdns0().Option = make([]dns.EDNS0, len(options))
	for index, option := range options {
		response.IsEdns0().Option[index] = option
	}
	return response
}
