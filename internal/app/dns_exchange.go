package app

import (
	"errors"

	"github.com/miekg/dns"
)

func (s *DNSServer) exchange(request *dns.Msg) (*dns.Msg, string, error) {
	config := s.configSnapshot()
	var candidates []string
	if s.pool != nil {
		candidates = s.pool.Candidates()
	}
	primaryErr := error(nil)
	if len(candidates) == 0 {
		primaryErr = errors.New("no healthy primary upstream")
	}
	upstreamRequest := request
	if (config.EnableDNSSEC || config.DNSSECValidate) && !request.CheckingDisabled && (request.IsEdns0() == nil || !request.IsEdns0().Do()) {
		upstreamRequest = request.Copy()
		ensureDNSSECRequest(upstreamRequest)
	}

	var response *dns.Msg
	var upstream string
	err := primaryErr
	if len(candidates) > 0 {
		switch config.UpstreamMode {
		case upstreamModeParallel:
			response, upstream, err = s.exchangeParallel(upstreamRequest, candidates, s.pool)
		case upstreamModeFastestAddr:
			response, upstream, err = s.exchangeFastestAddr(upstreamRequest, candidates, s.pool)
		default:
			response, upstream, err = s.exchangeLoadBalance(upstreamRequest, candidates, s.pool)
		}
		if err == nil && response != nil && !shouldRetryUpstreamResponse(response) {
			return response, upstream, nil
		}
	}

	fallbackCandidates := s.fallbackCandidates(config)
	if len(fallbackCandidates) == 0 {
		return response, upstream, err
	}
	fallbackResponse, fallbackUpstream, fallbackErr := s.exchangeLoadBalance(upstreamRequest, fallbackCandidates, s.fallbackPool)
	if fallbackErr == nil && fallbackResponse != nil && !shouldRetryUpstreamResponse(fallbackResponse) {
		return fallbackResponse, fallbackUpstream, nil
	}
	if response != nil {
		return response, upstream, nil
	}
	return fallbackResponse, fallbackUpstream, fallbackErr
}

func (s *DNSServer) fallbackCandidates(config Config) []string {
	if s.fallbackPool != nil {
		return s.fallbackPool.Candidates()
	}
	return append([]string(nil), config.FallbackUpstreams...)
}
