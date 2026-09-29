package app

import (
	"fmt"
	"net"
	"time"

	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
	"github.com/vigordns/vigordns/internal/dnsname"
	"github.com/vigordns/vigordns/internal/querylog"
	"github.com/vigordns/vigordns/internal/rules"
)

const maxBackgroundRefreshes int64 = 64

type resolveResult struct {
	response         *dns.Msg
	upstream         string
	dnssecValidated  bool
	rebindingBlocked bool
}

func queryClientIP(writer dns.ResponseWriter) string {
	if writer == nil || writer.RemoteAddr() == nil {
		return ""
	}
	address := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func (s *DNSServer) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		return
	}
	if request.Opcode != dns.OpcodeQuery {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeNotImplemented
		_ = writer.WriteMsg(response)
		return
	}
	if len(request.Question) != 1 {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeFormatError
		_ = writer.WriteMsg(response)
		return
	}
	if request.Question[0].Qtype == dns.TypeAXFR || request.Question[0].Qtype == dns.TypeIXFR {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeNotImplemented
		_ = writer.WriteMsg(response)
		return
	}
	if edns := request.IsEdns0(); edns != nil && edns.Version() != 0 {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeBadVers
		response.SetEdns0(edns.UDPSize(), false)
		_ = writer.WriteMsg(response)
		return
	}
	config := s.configSnapshot()
	generation := s.configGeneration()
	question := request.Question[0]
	domain := dnsname.Normalize(question.Name)
	queryType := dns.TypeToString[question.Qtype]
	started := time.Now()
	clientIP := queryClientIP(writer)
	logQuery := func(action, upstream string) {
		s.logs.Add(querylog.Entry{Time: time.Now().Format(time.RFC3339), Client: clientIP, Domain: domain, Type: queryType, Action: action, Upstream: upstream, Duration: time.Since(started).Milliseconds()})
	}
	if !s.clientAllowed(clientIP) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeRefused)
		_ = writer.WriteMsg(response)
		logQuery(querylog.ActionDenied, "")
		return
	}
	if !s.clientRateAllowed(clientIP) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeRefused)
		_ = writer.WriteMsg(response)
		logQuery(querylog.ActionRateLimited, "")
		return
	}
	if !s.acquireQuerySlot() {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = writer.WriteMsg(response)
		logQuery(querylog.ActionOverloaded, "")
		return
	}
	defer s.releaseQuerySlot()
	action, rewriteIP, matched := s.rules.Match(domain)
	if matched && action == rules.ActionAllow {
		action = "forwarded"
	}

	if matched && action == rules.ActionBlock {
		response := blockedResponse(request, question, &config)
		_ = writer.WriteMsg(filterUpstreamResponse(response, request))
		logQuery(string(rules.ActionBlock), "")
		return
	}
	if matched && action == rules.ActionRewrite && rewriteIP != nil {
		response := rewriteResponse(request, question, rewriteIP)
		if response != nil {
			_ = writer.WriteMsg(response)
			logQuery(string(rules.ActionRewrite), "")
			return
		}
	}
	if response, ok := s.localRecordResponse(request, question); ok {
		_ = writer.WriteMsg(filterUpstreamResponse(response, request))
		logQuery(querylog.ActionLocal, "")
		return
	}

	cacheKey, cacheRequest := makeCacheKey(request)
	if cacheRequest && config.CacheEnabled {
		if response, stale := s.cache.Get(cacheKey, config.OptimisticCache, config.OptimisticAnswerTTL, config.OptimisticMaxAge); response == nil {
			s.markDNSSECCache(cacheKey, false)
		} else {
			validated := config.DNSSECValidate && s.cachedDNSSECIsSecure(cacheKey)
			rebindingPolicy := s.accessPolicySnapshot()
			rebindingBlocked := false
			response, rebindingBlocked = filterRebindingResponse(response, question, rebindingPolicy)
			validated = validated && !rebindingBlocked
			response = filterCachedResponseWithDNSSEC(response, request, validated)
			_ = writer.WriteMsg(response)
			logAction := "cached"
			if rebindingBlocked {
				logAction = querylog.ActionRebindingBlocked
			}
			if stale {
				logAction = "optimistic"
				s.refreshInBackground(request.Copy(), cacheKey)
			}
			logQuery(logAction, "")
			return
		}
	}

	if !cacheRequest || !config.CacheEnabled {
		s.cache.RecordBypass()
	}
	coalesceKey := cacheKey
	if !cacheRequest {
		coalesceKey = requestCoalescingKey(request)
	}
	value, err, _ := s.inflight.Do(coalesceKey, func() (any, error) {
		response, upstream, err := s.exchange(request)
		if err != nil {
			return nil, err
		}
		rebindingPolicy := s.accessPolicySnapshot()
		rebindingBlocked := false
		response, rebindingBlocked = filterRebindingResponse(response, question, rebindingPolicy)
		validated := false
		if config.DNSSECValidate && !rebindingBlocked {
			result := s.validateDNSSEC(response, question)
			if isDNSSECValidationFailure(result) {
				return nil, fmt.Errorf("DNSSEC validation returned %s", result.String())
			}
			validated = result == blockydnssec.ValidationResultSecure
		}
		if cacheRequest && config.CacheEnabled && s.configGeneration() == generation {
			if cachedResponse, ttl, ok := prepareCacheResponseForRequest(request, response, &config); ok && s.cache.Set(cacheKey, cachedResponse, ttl, optimisticMaxAge(config.OptimisticMaxAge)) {
				response = cachedResponse
				s.markDNSSECCache(cacheKey, validated)
			} else {
				s.markDNSSECCache(cacheKey, false)
			}
		}
		return resolveResult{response: response, upstream: upstream, dnssecValidated: validated, rebindingBlocked: rebindingBlocked}, nil
	})
	if err != nil {
		failure := new(dns.Msg)
		failure.SetRcode(request, dns.RcodeServerFailure)
		_ = writer.WriteMsg(failure)
		logQuery(querylog.ActionError, "")
		return
	}
	result, ok := value.(resolveResult)
	if !ok || result.response == nil {
		failure := new(dns.Msg)
		failure.SetRcode(request, dns.RcodeServerFailure)
		_ = writer.WriteMsg(failure)
		logQuery(querylog.ActionError, "")
		return
	}

	clientResponse := filterResponseWithDNSSEC(result.response.Copy(), request, config.DNSSECValidate && result.dnssecValidated)
	clientResponse.Id = request.Id
	_ = writer.WriteMsg(clientResponse)
	logAction := string(rules.ActionAllow)
	if result.rebindingBlocked {
		logAction = querylog.ActionRebindingBlocked
	} else if action == "" {
		logAction = "forwarded"
	}
	logQuery(logAction, result.upstream)
}

func (s *DNSServer) acquireBackgroundRefreshSlot() bool {
	for {
		current := s.refreshInFlight.Load()
		if current >= maxBackgroundRefreshes {
			return false
		}
		if s.refreshInFlight.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (s *DNSServer) releaseBackgroundRefreshSlot() {
	s.refreshInFlight.Add(-1)
}

func (s *DNSServer) refreshInBackground(request *dns.Msg, key string) {
	if _, loaded := s.refreshing.LoadOrStore(key, true); loaded {
		return
	}
	if !s.acquireBackgroundRefreshSlot() {
		s.refreshing.Delete(key)
		return
	}
	generation := s.configGeneration()
	go func() {
		defer s.refreshing.Delete(key)
		defer s.releaseBackgroundRefreshSlot()
		response, _, err := s.exchange(request)
		if err != nil {
			s.cache.RecordRefresh(false)
			return
		}
		config := s.configSnapshot()
		if s.configGeneration() != generation {
			s.cache.RecordRefresh(false)
			return
		}
		rebindingPolicy := s.accessPolicySnapshot()
		rebindingBlocked := false
		response, rebindingBlocked = filterRebindingResponse(response, request.Question[0], rebindingPolicy)
		validated := false
		if config.DNSSECValidate && !rebindingBlocked {
			result := s.validateDNSSEC(response, request.Question[0])
			if isDNSSECValidationFailure(result) {
				s.markDNSSECCache(key, false)
				s.cache.RecordRefresh(false)
				return
			}
			validated = result == blockydnssec.ValidationResultSecure
		}
		if cachedResponse, ttl, ok := prepareCacheResponseForRequest(request, response, &config); ok && s.cache.Set(key, cachedResponse, ttl, optimisticMaxAge(config.OptimisticMaxAge)) {
			s.markDNSSECCache(key, validated)
			s.cache.RecordRefresh(true)
			return
		}
		s.markDNSSECCache(key, false)
		s.cache.RecordRefresh(false)
	}()
}
