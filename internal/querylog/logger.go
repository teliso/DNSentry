package querylog

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teliso/DNSentry/internal/rules"
)

// Actions recorded for queries that never reached an upstream or were
// rejected by policy. Rule outcomes use the rules.Action values.
const (
	ActionDenied           = "denied"
	ActionRateLimited      = "rate_limited"
	ActionOverloaded       = "overloaded"
	ActionRebindingBlocked = "rebinding_blocked"
	ActionLocal            = "local"
	ActionForwarded        = "forwarded"
	ActionCached           = "cached"
	ActionOptimistic       = "optimistic"
	ActionError            = "error"
)

type Entry struct {
	Time     string `json:"time"`
	Client   string `json:"client,omitempty"`
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Upstream string `json:"upstream,omitempty"`
	Duration int64  `json:"duration_ms"`
	// Rule is the filter rule that decided the query and RuleSource the list
	// it came from (empty for the local rules file).
	Rule       string `json:"rule,omitempty"`
	RuleSource string `json:"rule_source,omitempty"`
}

type MetricPoint struct {
	Time    string `json:"time"`
	Queries uint64 `json:"queries"`
	Blocked uint64 `json:"blocked"`
}

type DashboardCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type DashboardUpstream struct {
	Address           string `json:"address"`
	Count             uint64 `json:"count"`
	AverageDurationMS int64  `json:"average_duration_ms"`
}

type DashboardStats struct {
	AverageProcessingMS int64               `json:"average_processing_ms"`
	ClientIPs           []DashboardCount    `json:"client_ips"`
	Domains             []DashboardCount    `json:"domains"`
	BlockedDomains      []DashboardCount    `json:"blocked_domains"`
	Upstreams           []DashboardUpstream `json:"upstreams"`
}

type SecurityStats struct {
	DeniedClients    uint64 `json:"denied_clients"`
	RateLimited      uint64 `json:"rate_limited"`
	Overloaded       uint64 `json:"overloaded"`
	RebindingBlocked uint64 `json:"rebinding_blocked"`
}

type Logger struct {
	mu            sync.RWMutex
	entries       []Entry
	metrics       map[int64]MetricPoint
	max           int
	total         atomic.Uint64
	blocked       atomic.Uint64
	totalDuration atomic.Uint64
	denied        atomic.Uint64
	rateLimited   atomic.Uint64
	overloaded    atomic.Uint64
	rebinding     atomic.Uint64
	persistence   *persistence
}

// New returns an in-memory logger that keeps the newest max entries.
func New(max int) *Logger {
	if max < 1 {
		max = 1
	}
	return &Logger{max: max, metrics: make(map[int64]MetricPoint)}
}

func (l *Logger) Add(entry Entry) {
	l.total.Add(1)
	if entry.Duration > 0 {
		l.totalDuration.Add(uint64(entry.Duration))
	}
	if entry.Action == string(rules.ActionBlock) {
		l.blocked.Add(1)
	}
	switch entry.Action {
	case ActionDenied:
		l.denied.Add(1)
	case ActionRateLimited:
		l.rateLimited.Add(1)
	case ActionOverloaded:
		l.overloaded.Add(1)
	case ActionRebindingBlocked:
		l.rebinding.Add(1)
	}
	now := time.Now().Truncate(time.Minute)
	l.mu.Lock()
	// Newest-first ring: shift in place instead of reallocating per query.
	if len(l.entries) < l.max {
		l.entries = append(l.entries, Entry{})
	}
	copy(l.entries[1:], l.entries)
	l.entries[0] = entry
	bucket, exists := l.metrics[now.Unix()]
	if !exists {
		// A new minute started: drop buckets older than the retained window.
		bucket.Time = now.Format(time.RFC3339)
		cutoff := now.Add(-2 * time.Hour).Unix()
		for timestamp := range l.metrics {
			if timestamp < cutoff {
				delete(l.metrics, timestamp)
			}
		}
	}
	bucket.Queries++
	if entry.Action == string(rules.ActionBlock) {
		bucket.Blocked++
	}
	l.metrics[now.Unix()] = bucket
	l.mu.Unlock()
	l.enqueuePersistence(entry)
}

func (l *Logger) List() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Entry, len(l.entries))
	copy(result, l.entries)
	return result
}

func (l *Logger) Metrics() []MetricPoint {
	now := time.Now().Truncate(time.Minute)
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]MetricPoint, 0, 30)
	for index := 29; index >= 0; index-- {
		pointTime := now.Add(-time.Duration(index) * time.Minute)
		point := l.metrics[pointTime.Unix()]
		if point.Time == "" {
			point.Time = pointTime.Format(time.RFC3339)
		}
		result = append(result, point)
	}
	return result
}

func (l *Logger) Stats() (uint64, uint64) {
	return l.total.Load(), l.blocked.Load()
}

func (l *Logger) SecurityStats() SecurityStats {
	return SecurityStats{
		DeniedClients:    l.denied.Load(),
		RateLimited:      l.rateLimited.Load(),
		Overloaded:       l.overloaded.Load(),
		RebindingBlocked: l.rebinding.Load(),
	}
}

func (l *Logger) Dashboard() DashboardStats {
	total := l.total.Load()
	stats := DashboardStats{
		ClientIPs:      make([]DashboardCount, 0),
		Domains:        make([]DashboardCount, 0),
		BlockedDomains: make([]DashboardCount, 0),
		Upstreams:      make([]DashboardUpstream, 0),
	}
	if total > 0 {
		stats.AverageProcessingMS = int64(l.totalDuration.Load() / total)
	}

	entries := l.List()
	clients := make(map[string]uint64)
	domains := make(map[string]uint64)
	blocked := make(map[string]uint64)
	type upstreamAggregate struct {
		count    uint64
		duration int64
	}
	upstreams := make(map[string]upstreamAggregate)
	for _, entry := range entries {
		if entry.Client != "" {
			clients[entry.Client]++
		}
		if entry.Domain != "" {
			domains[entry.Domain]++
			if entry.Action == string(rules.ActionBlock) {
				blocked[entry.Domain]++
			}
		}
		if entry.Upstream != "" {
			aggregate := upstreams[entry.Upstream]
			aggregate.count++
			if entry.Duration > 0 {
				aggregate.duration += entry.Duration
			}
			upstreams[entry.Upstream] = aggregate
		}
	}
	stats.ClientIPs = dashboardCounts(clients, 10)
	stats.Domains = dashboardCounts(domains, 10)
	stats.BlockedDomains = dashboardCounts(blocked, 10)
	for address, aggregate := range upstreams {
		average := int64(0)
		if aggregate.count > 0 {
			average = aggregate.duration / int64(aggregate.count)
		}
		stats.Upstreams = append(stats.Upstreams, DashboardUpstream{Address: address, Count: aggregate.count, AverageDurationMS: average})
	}
	sort.Slice(stats.Upstreams, func(left, right int) bool {
		if stats.Upstreams[left].Count != stats.Upstreams[right].Count {
			return stats.Upstreams[left].Count > stats.Upstreams[right].Count
		}
		if stats.Upstreams[left].AverageDurationMS != stats.Upstreams[right].AverageDurationMS {
			return stats.Upstreams[left].AverageDurationMS < stats.Upstreams[right].AverageDurationMS
		}
		return stats.Upstreams[left].Address < stats.Upstreams[right].Address
	})
	if len(stats.Upstreams) > 10 {
		stats.Upstreams = stats.Upstreams[:10]
	}
	return stats
}

func dashboardCounts(values map[string]uint64, limit int) []DashboardCount {
	result := make([]DashboardCount, 0, len(values))
	for name, count := range values {
		result = append(result, DashboardCount{Name: name, Count: count})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Count != result[right].Count {
			return result[left].Count > result[right].Count
		}
		return result[left].Name < result[right].Name
	})
	if len(result) > limit {
		return result[:limit]
	}
	return result
}
