package app

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type upstreamTestResult struct {
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Success   bool   `json:"success"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (a *API) testUpstreams(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Upstreams []string `json:"upstreams"`
		Domain    string   `json:"domain"`
	}
	if !decodeJSON(writer, request, &input, "invalid test request") {
		return
	}
	if len(input.Upstreams) == 0 {
		input.Upstreams = a.resolver.configSnapshot().Upstreams
	}
	if len(input.Upstreams) > 32 {
		writeError(writer, http.StatusBadRequest, "too many upstreams")
		return
	}
	if input.Domain == "" {
		input.Domain = "example.com"
	}
	result := make([]upstreamTestResult, len(input.Upstreams))
	var wait sync.WaitGroup
	for index, address := range input.Upstreams {
		address = normalizeUpstream(strings.TrimSpace(address))
		result[index].Address = address
		wait.Add(1)
		go func(index int, address string) {
			defer wait.Done()
			started := time.Now()
			query := new(dns.Msg)
			query.SetQuestion(dns.Fqdn(input.Domain), dns.TypeA)
			_, err := a.resolver.exchangeUpstream(query, address)
			result[index] = upstreamTestResult{Address: address, Protocol: upstreamProtocol(address), Success: err == nil, LatencyMS: time.Since(started).Milliseconds()}
			if err != nil {
				result[index].Error = err.Error()
				a.resolver.pool.RecordFailure(address)
			} else {
				a.resolver.pool.RecordSuccess(address, time.Since(started))
			}
		}(index, address)
	}
	wait.Wait()
	writeJSON(writer, http.StatusOK, result)
}

func upstreamProtocol(address string) string {
	lower := strings.ToLower(address)
	switch {
	case strings.HasPrefix(lower, "h3://"):
		return "DoH3"
	case strings.HasPrefix(lower, "https://"):
		return "DoH"
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		return "DoT"
	case strings.HasPrefix(lower, "quic://"), strings.HasPrefix(lower, "doq://"):
		return "DoQ"
	default:
		return "DNS"
	}
}

func normalizeUpstream(value string) string {
	value = strings.TrimSpace(value)
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	if net.ParseIP(value) != nil {
		return net.JoinHostPort(value, "53")
	}
	return value
}
