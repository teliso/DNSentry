package app

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	upstreamModeLoadBalance = "load_balance"
	upstreamModeParallel    = "parallel"
	upstreamModeFastestAddr = "fastest_addr"

	maxUpstreamAttempts      = 3
	fastestAddrProbePort     = "443"
	fastestAddrProbeTimeout  = 750 * time.Millisecond
	maxFastestAddrCandidates = 16
)

type addressProbeFunc func(net.IP) (time.Duration, bool)

type upstreamQueryResult struct {
	response *dns.Msg
	upstream string
	latency  time.Duration
	err      error
	retry    bool
}

type addressProbeResult struct {
	latency time.Duration
	ok      bool
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

func (s *DNSServer) exchangeFastestAddr(request *dns.Msg, candidates []string, pool *UpstreamPool) (*dns.Msg, string, error) {
	if len(candidates) == 1 {
		return s.exchangeLoadBalance(request, candidates, pool)
	}

	results := s.queryAllUpstreams(request, candidates, pool)
	valid := make([]upstreamQueryResult, 0, len(candidates))
	var fallback *upstreamQueryResult
	var lastErr error
	var lastUpstream string
	for range candidates {
		result := <-results
		if result.response != nil && !result.retry {
			valid = append(valid, result)
			continue
		}
		if result.response != nil {
			fallback = &result
		}
		if result.err != nil {
			lastErr = result.err
		}
		lastUpstream = result.upstream
	}
	if len(valid) == 0 {
		return noUsableUpstreamResponse(fallback, lastUpstream, lastErr)
	}

	best := fastestDNSResponse(valid)
	probes := s.probeResponseAddresses(valid)
	bestProbeLatency := time.Duration(0)
	var bestAddress net.IP
	hasProbe := false
	for _, result := range valid {
		for _, ip := range responseAddresses(result.response) {
			probe, ok := probes[ip.String()]
			if !ok || !probe.ok {
				continue
			}
			if !hasProbe || probe.latency < bestProbeLatency || (probe.latency == bestProbeLatency && result.latency < best.latency) {
				best = result
				bestProbeLatency = probe.latency
				bestAddress = ip
				hasProbe = true
			}
		}
	}
	if hasProbe {
		return prioritizeResponseAddress(best.response, bestAddress), best.upstream, nil
	}
	return best.response, best.upstream, nil
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

func fastestDNSResponse(results []upstreamQueryResult) upstreamQueryResult {
	best := results[0]
	for _, result := range results[1:] {
		if result.latency < best.latency {
			best = result
		}
	}
	return best
}

func (s *DNSServer) probeResponseAddresses(results []upstreamQueryResult) map[string]addressProbeResult {
	addresses := make(map[string]net.IP)
	for _, result := range results {
		for _, ip := range responseAddresses(result.response) {
			if len(addresses) >= maxFastestAddrCandidates {
				break
			}
			addresses[ip.String()] = ip
		}
	}
	if len(addresses) == 0 {
		return nil
	}

	resultsChannel := make(chan struct {
		address string
		result  addressProbeResult
	}, len(addresses))
	for address, ip := range addresses {
		address, ip := address, ip
		go func() {
			latency, ok := s.probeAddress(ip)
			resultsChannel <- struct {
				address string
				result  addressProbeResult
			}{address: address, result: addressProbeResult{latency: latency, ok: ok}}
		}()
	}

	probes := make(map[string]addressProbeResult, len(addresses))
	for range addresses {
		result := <-resultsChannel
		probes[result.address] = result.result
	}
	return probes
}

func prioritizeResponseAddress(response *dns.Msg, address net.IP) *dns.Msg {
	if response == nil || address == nil {
		return response
	}
	copy := response.Copy()
	first := -1
	selected := -1
	for index, answer := range copy.Answer {
		var ip net.IP
		switch record := answer.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			continue
		}
		if !sameAddressFamily(ip, address) {
			continue
		}
		if first == -1 {
			first = index
		}
		if ip.Equal(address) {
			selected = index
			break
		}
	}
	if first >= 0 && selected > first {
		copy.Answer[first], copy.Answer[selected] = copy.Answer[selected], copy.Answer[first]
	}
	return copy
}

func sameAddressFamily(left, right net.IP) bool {
	return (left.To4() != nil) == (right.To4() != nil)
}

func responseAddresses(response *dns.Msg) []net.IP {
	if response == nil {
		return nil
	}
	addresses := make([]net.IP, 0)
	seen := make(map[string]struct{})
	for _, answer := range response.Answer {
		var ip net.IP
		switch record := answer.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			continue
		}
		if !isProbeableAddress(ip) {
			continue
		}
		key := ip.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		addresses = append(addresses, ip)
	}
	return addresses
}

func isProbeableAddress(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func (s *DNSServer) probeAddress(ip net.IP) (time.Duration, bool) {
	if s.fastestAddrProbe != nil {
		return s.fastestAddrProbe(ip)
	}
	started := time.Now()
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), fastestAddrProbePort), fastestAddrProbeTimeout)
	if err != nil {
		return time.Since(started), false
	}
	_ = connection.Close()
	return time.Since(started), true
}
