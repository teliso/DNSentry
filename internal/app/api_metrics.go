package app

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (a *API) writeMetrics(writer http.ResponseWriter, _ *http.Request) {
	stats := a.cache.Stats()
	total, blocked := a.logs.Stats()
	security := a.logs.SecurityStats()
	metrics := []struct {
		name, kind string
		value      any
	}{
		{"vigordns_dns_queries_total", "counter", total},
		{"vigordns_dns_blocked_total", "counter", blocked},
		{"vigordns_dns_access_denied_total", "counter", security.DeniedClients},
		{"vigordns_dns_rate_limited_total", "counter", security.RateLimited},
		{"vigordns_dns_overloaded_total", "counter", security.Overloaded},
		{"vigordns_dns_rebinding_blocked_total", "counter", security.RebindingBlocked},
		{"vigordns_cache_entries", "gauge", stats.Entries},
		{"vigordns_cache_used_bytes", "gauge", stats.UsedBytes},
		{"vigordns_cache_max_bytes", "gauge", stats.MaxBytes},
		{"vigordns_cache_hits_total", "counter", stats.Hits},
		{"vigordns_cache_misses_total", "counter", stats.Misses},
		{"vigordns_cache_stale_hits_total", "counter", stats.StaleHits},
		{"vigordns_cache_bypasses_total", "counter", stats.Bypasses},
		{"vigordns_cache_evictions_total", "counter", stats.Evictions},
		{"vigordns_cache_refresh_success_total", "counter", stats.RefreshSuccess},
		{"vigordns_cache_refresh_failure_total", "counter", stats.RefreshFailure},
		{"vigordns_cache_hit_rate", "gauge", fmt.Sprintf("%f", stats.HitRate)},
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(writer, "# TYPE %s %s\n%s %v\n", metric.name, metric.kind, metric.name, metric.value)
	}
	if a.resolver == nil {
		return
	}
	writeUpstreamPoolMetrics(writer, "primary", a.resolver.pool)
	writeUpstreamPoolMetrics(writer, "fallback", a.resolver.fallbackPool)
}

func writeUpstreamPoolMetrics(writer io.Writer, role string, pool *UpstreamPool) {
	if pool == nil {
		return
	}
	for _, health := range pool.Health() {
		labels := fmt.Sprintf(`role="%s",upstream="%s"`, prometheusLabel(role), prometheusLabel(health.Address))
		_, _ = fmt.Fprintf(writer, "vigordns_upstream_requests_total{%s} %d\nvigordns_upstream_successes_total{%s} %d\nvigordns_upstream_consecutive_failures{%s} %d\nvigordns_upstream_latency_milliseconds{%s} %d\n", labels, health.Requests, labels, health.Successes, labels, health.Failures, labels, health.LatencyMS)
	}
}

func prometheusLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}
