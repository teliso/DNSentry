package app

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (a *API) writeMetrics(writer http.ResponseWriter) {
	stats := a.cache.Stats()
	total, blocked := a.logs.Stats()
	security := a.logs.SecurityStats()
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(writer, "# TYPE vigordns_dns_queries_total counter\nvigordns_dns_queries_total %d\n# TYPE vigordns_dns_blocked_total counter\nvigordns_dns_blocked_total %d\n# TYPE vigordns_dns_access_denied_total counter\nvigordns_dns_access_denied_total %d\n# TYPE vigordns_dns_rate_limited_total counter\nvigordns_dns_rate_limited_total %d\n# TYPE vigordns_dns_overloaded_total counter\nvigordns_dns_overloaded_total %d\n# TYPE vigordns_dns_rebinding_blocked_total counter\nvigordns_dns_rebinding_blocked_total %d\n# TYPE vigordns_cache_entries gauge\nvigordns_cache_entries %d\n# TYPE vigordns_cache_used_bytes gauge\nvigordns_cache_used_bytes %d\n# TYPE vigordns_cache_max_bytes gauge\nvigordns_cache_max_bytes %d\n# TYPE vigordns_cache_hits_total counter\nvigordns_cache_hits_total %d\n# TYPE vigordns_cache_misses_total counter\nvigordns_cache_misses_total %d\n# TYPE vigordns_cache_stale_hits_total counter\nvigordns_cache_stale_hits_total %d\n# TYPE vigordns_cache_bypasses_total counter\nvigordns_cache_bypasses_total %d\n# TYPE vigordns_cache_evictions_total counter\nvigordns_cache_evictions_total %d\n# TYPE vigordns_cache_refresh_success_total counter\nvigordns_cache_refresh_success_total %d\n# TYPE vigordns_cache_refresh_failure_total counter\nvigordns_cache_refresh_failure_total %d\n# TYPE vigordns_cache_hit_rate gauge\nvigordns_cache_hit_rate %f\n", total, blocked, security.DeniedClients, security.RateLimited, security.Overloaded, security.RebindingBlocked, stats.Entries, stats.UsedBytes, stats.MaxBytes, stats.Hits, stats.Misses, stats.StaleHits, stats.Bypasses, stats.Evictions, stats.RefreshSuccess, stats.RefreshFailure, stats.HitRate)
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
