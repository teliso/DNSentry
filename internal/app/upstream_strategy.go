package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const (
	upstreamModeLoadBalance = "load_balance"
	upstreamModeParallel    = "parallel"

	maxUpstreamAttempts = 3
)

type upstreamQueryResult struct {
	response *dns.Msg
	upstream string
	latency  time.Duration
	err      error
	retry    bool
}

func (s *DNSServer) exchangeLoadBalance(request *dns.Msg, candidates []string, pool *UpstreamPool) (*dns.Msg, string, error) {
	var fallback *upstreamQueryResult
	var lastErr error
	var lastUpstream string
	for index, upstream := range candidates {
		if index >= maxUpstreamAttempts {
			break
		}
		result := s.queryUpstream(request, upstream, pool)
		if result.response != nil && !result.retry {
			return result.response, result.upstream, nil
		}
		if result.response != nil {
			fallback = &result
		}
		if result.err != nil {
			lastErr = result.err
		}
		lastUpstream = result.upstream
	}
	return noUsableUpstreamResponse(fallback, lastUpstream, lastErr)
}

func (s *DNSServer) exchangeParallel(request *dns.Msg, candidates []string, pool *UpstreamPool) (*dns.Msg, string, error) {
	results := s.queryAllUpstreams(request, candidates, pool)
	var fallback *upstreamQueryResult
	var lastErr error
	var lastUpstream string
	for range candidates {
		result := <-results
		if result.response != nil && !result.retry {
			return result.response, result.upstream, nil
		}
		if result.response != nil {
			fallback = &result
		}
		if result.err != nil {
			lastErr = result.err
		}
		lastUpstream = result.upstream
	}
	return noUsableUpstreamResponse(fallback, lastUpstream, lastErr)
}

func (s *DNSServer) queryAllUpstreams(request *dns.Msg, candidates []string, pool *UpstreamPool) <-chan upstreamQueryResult {
	results := make(chan upstreamQueryResult, len(candidates))
	for _, upstream := range candidates {
		upstream := upstream
		go func() {
			results <- s.queryUpstream(request.Copy(), upstream, pool)
		}()
	}
	return results
}

func (s *DNSServer) queryUpstream(request *dns.Msg, upstream string, pool *UpstreamPool) upstreamQueryResult {
	started := time.Now()
	response, err := s.exchangeUpstream(request, upstream)
	latency := time.Since(started)
	result := upstreamQueryResult{response: response, upstream: upstream, latency: latency, err: err}
	if err != nil {
		if pool != nil {
			pool.RecordFailure(upstream)
		}
		return result
	}
	if shouldRetryUpstreamResponse(response) {
		result.retry = true
		result.err = fmt.Errorf("upstream returned %s", dns.RcodeToString[response.Rcode])
		if pool != nil {
			pool.RecordFailure(upstream)
		}
		return result
	}
	if pool != nil {
		pool.RecordSuccess(upstream, latency)
	}
	return result
}

func noUsableUpstreamResponse(fallback *upstreamQueryResult, lastUpstream string, lastErr error) (*dns.Msg, string, error) {
	if fallback != nil {
		return fallback.response, fallback.upstream, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable upstream response")
	}
	return nil, lastUpstream, lastErr
}
