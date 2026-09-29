package app

import (
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/dnsname"
)

func optimisticMaxAge(seconds uint32) time.Duration {
	if seconds == 0 {
		return time.Duration(cache.DefaultOptimisticMaxAgeSeconds) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func prepareCacheResponse(message *dns.Msg, config *Config) (*dns.Msg, uint32, bool) {
	if !isCacheableResponse(message) {
		return message, 0, false
	}
	cached := message.Copy()
	if cached.Rcode == dns.RcodeServerFailure {
		return cached, cache.ServfailTTL, true
	}
	cache.ClampTTL(cached, config.CacheTTLMin, config.CacheTTLMax)
	ttl := cacheResponseTTL(cached)
	if ttl == 0 {
		return message, 0, false
	}
	return cached, ttl, true
}

func prepareCacheResponseForRequest(request, response *dns.Msg, config *Config) (*dns.Msg, uint32, bool) {
	if !hasECSOption(request) {
		return prepareCacheResponse(response, config)
	}
	if _, ok := validateECSRequest(request); !ok {
		return response, 0, false
	}
	validated, ok := validateECSResponse(request, response)
	if !ok {
		return response, 0, false
	}
	cached, ttl, ok := prepareCacheResponse(response, config)
	if !ok {
		return cached, ttl, false
	}
	if !replaceECSOption(cached, validated) {
		return response, 0, false
	}
	return cached, ttl, true
}

func isCacheableResponse(message *dns.Msg) bool {
	if message == nil || message.Opcode != dns.OpcodeQuery || message.Truncated || len(message.Question) != 1 {
		return false
	}
	question := message.Question[0]
	switch message.Rcode {
	case dns.RcodeServerFailure:
		return true
	case dns.RcodeNameError:
		return isCacheableNegative(message)
	case dns.RcodeSuccess:
		if hasAnswerForType(message, question.Qtype) {
			return true
		}
		return isCacheableNegative(message)
	default:
		return false
	}
}

func hasAnswerForType(message *dns.Msg, qtype uint16) bool {
	if len(message.Answer) == 0 {
		return false
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return true
	}
	for _, record := range message.Answer {
		if record.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func isCacheableNegative(message *dns.Msg) bool {
	if len(message.Answer) != 0 || len(message.Ns) == 0 {
		return false
	}
	seenSOA := false
	for _, record := range message.Ns {
		switch record.(type) {
		case *dns.SOA:
			seenSOA = true
		case *dns.NS:
			return false
		}
	}
	return seenSOA
}

func filterResponseWithDNSSEC(message, request *dns.Msg, locallyValidated bool) *dns.Msg {
	response := normalizeClientResponse(message, request, false)
	if locallyValidated && request != nil && request.AuthenticatedData && !request.CheckingDisabled {
		response.AuthenticatedData = true
	}
	return response
}

func filterCachedResponseWithDNSSEC(message, request *dns.Msg, locallyValidated bool) *dns.Msg {
	response := normalizeClientResponse(message, request, true)
	if locallyValidated && request != nil && request.AuthenticatedData && !request.CheckingDisabled {
		response.AuthenticatedData = true
	}
	return response
}

func filterUpstreamResponse(message, request *dns.Msg) *dns.Msg {
	return normalizeClientResponse(message, request, false)
}

func normalizeClientResponse(message, request *dns.Msg, cached bool) *dns.Msg {
	message.Id = request.Id
	message.Question = append([]dns.Question(nil), request.Question...)
	message.AuthenticatedData = false
	if request.IsEdns0() == nil || !request.IsEdns0().Do() {
		filterDNSSECRecords(message)
	}
	var responseECS *dns.EDNS0_SUBNET
	if cached {
		responseECS = cachedECSForRequest(message, request)
	}
	if cached || request.IsEdns0() == nil || len(request.IsEdns0().Option) == 0 {
		filteredExtra := message.Extra[:0]
		for _, record := range message.Extra {
			if _, isOPT := record.(*dns.OPT); !isOPT {
				filteredExtra = append(filteredExtra, record)
			}
		}
		message.Extra = filteredExtra
		if edns := request.IsEdns0(); edns != nil {
			opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: edns.UDPSize()}}
			opt.SetDo(edns.Do())
			if responseECS != nil && requestECSOption(request) {
				opt.Option = append(opt.Option, responseECS)
			}
			message.Extra = append(message.Extra, opt)
		}
	}
	return message
}

func filterDNSSECRecords(message *dns.Msg) {
	filter := func(records []dns.RR) []dns.RR {
		filtered := records[:0]
		for _, record := range records {
			switch record.(type) {
			case *dns.DNSKEY, *dns.DS, *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.NSEC3PARAM:
				continue
			default:
				filtered = append(filtered, record)
			}
		}
		return filtered
	}
	message.Answer = filter(message.Answer)
	message.Ns = filter(message.Ns)
	message.Extra = filter(message.Extra)
}

func makeCacheKey(request *dns.Msg) (string, bool) {
	if request == nil || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 || request.CheckingDisabled {
		return "", false
	}
	question := request.Question[0]
	if question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR || question.Qtype == dns.TypeANY {
		return "", false
	}
	domain := dnsname.Normalize(question.Name)
	if domain == "" {
		return "", false
	}
	var ecsKey string
	if edns := request.IsEdns0(); edns != nil {
		for _, option := range edns.Option {
			subnet, isSubnet := option.(*dns.EDNS0_SUBNET)
			if isSubnet {
				if ecsKey != "" {
					return "", false
				}
				ecsKey = normalizedECSKey(subnet)
				if ecsKey == "" {
					return "", false
				}
				continue
			}
			// Cookies, padding, NSID, and unknown options are not safe to
			// share between clients, so they bypass the cache.
			return "", false
		}
	}
	key := fmt.Sprintf("%s:%d:%d:rd=%t:cd=%t:do=%t", domain, question.Qtype, question.Qclass, request.RecursionDesired, request.CheckingDisabled, request.IsEdns0() != nil && request.IsEdns0().Do())
	if ecsKey != "" {
		key += ":ecs=" + ecsKey
	}
	return key, true
}

func normalizedECSKey(subnet *dns.EDNS0_SUBNET) string {
	if subnet == nil || (subnet.Family != 1 && subnet.Family != 2) {
		return ""
	}
	bits := 128
	ip := subnet.Address.To16()
	if subnet.Family == 1 {
		bits = 32
		ip = subnet.Address.To4()
	}
	if ip == nil || int(subnet.SourceNetmask) > bits {
		return ""
	}
	masked := ip.Mask(net.CIDRMask(int(subnet.SourceNetmask), bits))
	if masked == nil {
		return ""
	}
	return fmt.Sprintf("%d/%d/%s", subnet.Family, subnet.SourceNetmask, masked.String())
}

func requestECSOption(request *dns.Msg) bool {
	return hasECSOption(request)
}

func hasECSOption(message *dns.Msg) bool {
	if message == nil {
		return false
	}
	if edns := message.IsEdns0(); edns != nil {
		for _, option := range edns.Option {
			if _, ok := option.(*dns.EDNS0_SUBNET); ok {
				return true
			}
		}
	}
	return false
}

func validateECSRequest(request *dns.Msg) (*dns.EDNS0_SUBNET, bool) {
	if request == nil || request.IsEdns0() == nil {
		return nil, false
	}
	var subnet *dns.EDNS0_SUBNET
	for _, option := range request.IsEdns0().Option {
		candidate, ok := option.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		if subnet != nil {
			return nil, false
		}
		subnet = candidate
	}
	if subnet == nil {
		return nil, false
	}
	address, bits, ok := ecsAddress(subnet)
	if !ok || int(subnet.SourceNetmask) > bits || subnet.SourceScope != 0 {
		return nil, false
	}
	copy := *subnet
	copy.Address = append(net.IP(nil), address...)
	return &copy, true
}

func validateECSResponse(request, response *dns.Msg) (*dns.EDNS0_SUBNET, bool) {
	requestECS, ok := validateECSRequest(request)
	if !ok {
		return nil, false
	}
	responseECS, ok := singleECSOption(response)
	if !ok || responseECS.Family != requestECS.Family || responseECS.SourceNetmask != requestECS.SourceNetmask {
		return nil, false
	}
	requestAddress, bits, ok := ecsAddress(requestECS)
	if !ok || int(responseECS.SourceNetmask) > bits || int(responseECS.SourceScope) > bits || responseECS.SourceScope > responseECS.SourceNetmask {
		return nil, false
	}
	responseAddress, _, ok := ecsAddress(responseECS)
	if !ok {
		return nil, false
	}
	sourceMask := net.CIDRMask(int(requestECS.SourceNetmask), bits)
	if sourceMask == nil || !responseAddress.Equal(responseAddress.Mask(sourceMask)) {
		return nil, false
	}
	scopeMask := net.CIDRMask(int(responseECS.SourceScope), bits)
	if scopeMask == nil || !responseAddress.Mask(scopeMask).Equal(requestAddress.Mask(scopeMask)) {
		return nil, false
	}
	validated := *responseECS
	validated.Address = append(net.IP(nil), responseAddress.Mask(sourceMask)...)
	return &validated, true
}

func ecsAddress(subnet *dns.EDNS0_SUBNET) (net.IP, int, bool) {
	if subnet == nil {
		return nil, 0, false
	}
	switch subnet.Family {
	case 1:
		address := subnet.Address.To4()
		if address == nil {
			return nil, 0, false
		}
		return append(net.IP(nil), address...), 32, true
	case 2:
		if subnet.Address == nil || subnet.Address.To4() != nil {
			return nil, 0, false
		}
		address := subnet.Address.To16()
		if address == nil {
			return nil, 0, false
		}
		return append(net.IP(nil), address...), 128, true
	default:
		return nil, 0, false
	}
}

func singleECSOption(message *dns.Msg) (*dns.EDNS0_SUBNET, bool) {
	if message == nil {
		return nil, false
	}
	var subnet *dns.EDNS0_SUBNET
	for _, record := range message.Extra {
		opt, ok := record.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			candidate, ok := option.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			if subnet != nil {
				return nil, false
			}
			subnet = candidate
		}
	}
	return subnet, subnet != nil
}

func replaceECSOption(message *dns.Msg, replacement *dns.EDNS0_SUBNET) bool {
	if message == nil || replacement == nil {
		return false
	}
	for _, record := range message.Extra {
		opt, ok := record.(*dns.OPT)
		if !ok {
			continue
		}
		for index, option := range opt.Option {
			if _, ok := option.(*dns.EDNS0_SUBNET); !ok {
				continue
			}
			copy := *replacement
			copy.Address = append(net.IP(nil), replacement.Address...)
			opt.Option[index] = &copy
			return true
		}
	}
	return false
}

func cachedECSForRequest(message, request *dns.Msg) *dns.EDNS0_SUBNET {
	requestECS, ok := validateECSRequest(request)
	if !ok {
		return nil
	}
	cachedECS, ok := validateECSResponse(request, message)
	if !ok {
		return nil
	}
	address, bits, ok := ecsAddress(requestECS)
	if !ok {
		return nil
	}
	cachedECS.Address = append(net.IP(nil), address.Mask(net.CIDRMask(int(requestECS.SourceNetmask), bits))...)
	cachedECS.Family = requestECS.Family
	cachedECS.SourceNetmask = requestECS.SourceNetmask
	return cachedECS
}

func requestCoalescingKey(request *dns.Msg) string {
	copy := request.Copy()
	copy.Id = 0
	packet, err := copy.Pack()
	if err != nil {
		return fmt.Sprintf("request:%p", request)
	}
	digest := sha256.Sum256(packet)
	return fmt.Sprintf("request:%x", digest)
}

func shouldRetryUpstreamResponse(response *dns.Msg) bool {
	return response != nil && (response.Rcode == dns.RcodeServerFailure || response.Rcode == dns.RcodeRefused)
}

func ensureDNSSECRequest(request *dns.Msg) {
	if edns := request.IsEdns0(); edns != nil {
		edns.SetDo(true)
		return
	}
	request.SetEdns0(1232, true)
}

func blockedResponse(request *dns.Msg, question dns.Question, config *Config) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	mode := config.BlockingMode
	if mode == "" {
		mode = "default"
	}
	if mode == "refused" {
		response.Rcode = dns.RcodeRefused
		return response
	}
	if mode == "nxdomain" {
		response.Rcode = dns.RcodeNameError
		ttl := config.BlockedResponseTTL
		if ttl == 0 {
			ttl = 10
		}
		response.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: question.Qclass, Ttl: ttl},
			Ns:      "localhost.",
			Mbox:    "hostmaster.localhost.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  ttl,
		}}
		return response
	}
	if mode == "default" {
		mode = "null_ip"
	}

	ipv4 := net.ParseIP(config.BlockingIPv4)
	ipv6 := net.ParseIP(config.BlockingIPv6)
	if mode != "custom_ip" || ipv4 == nil || ipv4.To4() == nil {
		ipv4 = net.IPv4zero
	} else {
		ipv4 = ipv4.To4()
	}
	if mode != "custom_ip" || ipv6 == nil || ipv6.To4() != nil || ipv6.To16() == nil {
		ipv6 = net.IPv6unspecified
	} else {
		ipv6 = ipv6.To16()
	}
	ttl := config.BlockedResponseTTL
	if ttl == 0 {
		ttl = 10
	}
	header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: question.Qclass, Ttl: ttl}
	switch question.Qtype {
	case dns.TypeA:
		response.Answer = append(response.Answer, &dns.A{Hdr: header, A: ipv4.To4()})
	case dns.TypeAAAA:
		header.Rrtype = dns.TypeAAAA
		response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: ipv6.To16()})
	}
	return response
}

func responseTTL(message *dns.Msg) uint32 {
	if message == nil {
		return 0
	}
	var ttl uint32
	found := false
	visit := func(records []dns.RR) {
		for _, record := range records {
			if _, isOPT := record.(*dns.OPT); isOPT {
				continue
			}
			current := record.Header().Ttl
			if !found || current < ttl {
				ttl = current
				found = true
			}
		}
	}
	visit(message.Answer)
	visit(message.Ns)
	visit(message.Extra)
	if !found {
		return 0
	}
	return ttl
}

func cacheResponseTTL(message *dns.Msg) uint32 {
	ttl := responseTTL(message)
	if message == nil || (message.Rcode != dns.RcodeNameError && !(message.Rcode == dns.RcodeSuccess && len(message.Answer) == 0)) {
		return ttl
	}
	for _, record := range message.Ns {
		if soa, ok := record.(*dns.SOA); ok && soa.Minttl < ttl {
			ttl = soa.Minttl
		}
	}
	return ttl
}
