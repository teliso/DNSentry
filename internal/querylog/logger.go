package querylog

import (
	"sort"
	"strings"
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
	ActionIPv6Off          = "aaaa_blocked"
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

// DashboardDuration is a domain with the average time its upstream
// resolutions took.
type DashboardDuration struct {
	Name              string `json:"name"`
	Count             uint64 `json:"count"`
	AverageDurationMS int64  `json:"average_duration_ms"`
}

type DashboardStats struct {
	SlowDomains         []DashboardDuration `json:"slow_domains"`
	FailedDomains       []DashboardCount    `json:"failed_domains"`
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
		SlowDomains:    make([]DashboardDuration, 0),
		FailedDomains:  make([]DashboardCount, 0),
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
	resolved := make(map[string]upstreamAggregate) // domain -> upstream resolutions
	failed := make(map[string]uint64)
	for _, entry := range entries {
		if entry.Action == ActionError && entry.Domain != "" {
			failed[entry.Domain]++
		}
		if entry.Upstream != "" && entry.Domain != "" {
			aggregate := resolved[entry.Domain]
			aggregate.count++
			aggregate.duration += max(entry.Duration, 0)
			resolved[entry.Domain] = aggregate
		}
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
	stats.FailedDomains = dashboardCounts(failed, 10)
	for name, aggregate := range resolved {
		stats.SlowDomains = append(stats.SlowDomains, DashboardDuration{Name: name, Count: aggregate.count, AverageDurationMS: aggregate.duration / int64(aggregate.count)})
	}
	sort.Slice(stats.SlowDomains, func(left, right int) bool {
		a, b := stats.SlowDomains[left], stats.SlowDomains[right]
		if a.AverageDurationMS != b.AverageDurationMS {
			return a.AverageDurationMS > b.AverageDurationMS
		}
		return a.Name < b.Name
	})
	if len(stats.SlowDomains) > 10 {
		stats.SlowDomains = stats.SlowDomains[:10]
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

// Filter selects entries for Query.
type Filter struct {
	Search string // substring of the domain or client address
	Action string // exact action, empty for any
	Offset int
	Limit  int
}

// Page is one page of entries, newest first, plus the actions present in the
// whole log so clients can offer them as filters.
type Page struct {
	Total   int      `json:"total"`
	Items   []Entry  `json:"items"`
	Actions []string `json:"actions"`
}

const maxPageSize = 500

// Query returns the entries matching filter, newest first.
func (l *Logger) Query(filter Filter) Page {
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	limit := filter.Limit
	if limit <= 0 || limit > maxPageSize {
		limit = 100
	}
	offset := max(filter.Offset, 0)
	page := Page{Items: []Entry{}, Actions: []string{}}
	seen := map[string]bool{}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, entry := range l.entries {
		if !seen[entry.Action] {
			seen[entry.Action] = true
			page.Actions = append(page.Actions, entry.Action)
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if search != "" && !strings.Contains(entry.Domain, search) && !strings.Contains(entry.Client, search) {
			continue
		}
		if page.Total >= offset && len(page.Items) < limit {
			page.Items = append(page.Items, entry)
		}
		page.Total++
	}
	sort.Strings(page.Actions)
	return page
}
