package app

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type QueryLogEntry struct {
	Time     string `json:"time"`
	Client   string `json:"client,omitempty"`
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Upstream string `json:"upstream,omitempty"`
	Duration int64  `json:"duration_ms"`
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

type QueryLogger struct {
	mu            sync.RWMutex
	entries       []QueryLogEntry
	metrics       map[int64]MetricPoint
	max           int
	total         atomic.Uint64
	blocked       atomic.Uint64
	totalDuration atomic.Uint64
	denied        atomic.Uint64
	rateLimited   atomic.Uint64
	overloaded    atomic.Uint64
	rebinding     atomic.Uint64
	persistence   *queryLogPersistence
}

func NewQueryLogger(max int) *QueryLogger {
	return newQueryLogger(max)
}

func newQueryLogger(max int) *QueryLogger {
	if max < 1 {
		max = 1
	}
	return &QueryLogger{max: max, metrics: make(map[int64]MetricPoint)}
}

func (l *QueryLogger) Add(entry QueryLogEntry) {
	l.total.Add(1)
	if entry.Duration > 0 {
		l.totalDuration.Add(uint64(entry.Duration))
	}
	if entry.Action == string(ActionBlock) {
		l.blocked.Add(1)
	}
	switch entry.Action {
	case "denied":
		l.denied.Add(1)
	case "rate_limited":
		l.rateLimited.Add(1)
	case "overloaded":
		l.overloaded.Add(1)
	case "rebinding_blocked":
		l.rebinding.Add(1)
	}
	now := time.Now().Truncate(time.Minute)
	l.mu.Lock()
	l.entries = append([]QueryLogEntry{entry}, l.entries...)
	if len(l.entries) > l.max {
		l.entries = l.entries[:l.max]
	}
	bucket := l.metrics[now.Unix()]
	bucket.Time = now.Format(time.RFC3339)
	bucket.Queries++
	if entry.Action == string(ActionBlock) {
		bucket.Blocked++
	}
	l.metrics[now.Unix()] = bucket
	for timestamp := range l.metrics {
		if timestamp < now.Add(-2*time.Hour).Unix() {
			delete(l.metrics, timestamp)
		}
	}
	l.mu.Unlock()
	l.enqueuePersistence(entry)
}

func (l *QueryLogger) List() []QueryLogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]QueryLogEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

func (l *QueryLogger) Metrics() []MetricPoint {
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

func (l *QueryLogger) Stats() (uint64, uint64) {
	return l.total.Load(), l.blocked.Load()
}

func (l *QueryLogger) SecurityStats() SecurityStats {
	return SecurityStats{
		DeniedClients:    l.denied.Load(),
		RateLimited:      l.rateLimited.Load(),
		Overloaded:       l.overloaded.Load(),
		RebindingBlocked: l.rebinding.Load(),
	}
}

func (l *QueryLogger) Dashboard() DashboardStats {
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
			if entry.Action == string(ActionBlock) {
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
