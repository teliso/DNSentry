package rules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Source struct {
	URL             string `json:"url" yaml:"url"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	IntervalMinutes int    `json:"interval_minutes" yaml:"interval_minutes"`
	LastUpdated     string `json:"last_updated,omitempty" yaml:"last_updated,omitempty"`
	LastError       string `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	RuleCount       int    `json:"rule_count" yaml:"rule_count"`
}

type Updater struct {
	store   *Store
	client  *http.Client
	mu      sync.RWMutex
	sources map[string]Source
}

func NewUpdater(store *Store, sources []Source) *Updater {
	updater := &Updater{
		store:   store,
		client:  &http.Client{Timeout: 20 * time.Second},
		sources: make(map[string]Source),
	}
	updater.SetSources(sources)
	return updater
}

func (u *Updater) SetSources(sources []Source) {
	u.mu.RLock()
	previousSources := make(map[string]Source, len(u.sources))
	for sourceURL, source := range u.sources {
		previousSources[sourceURL] = source
	}
	u.mu.RUnlock()

	next := make(map[string]Source, len(sources))
	for _, source := range sources {
		source.URL = strings.TrimSpace(source.URL)
		if source.URL == "" {
			continue
		}
		if source.IntervalMinutes < 1 {
			source.IntervalMinutes = 360
		}
		if previous, exists := previousSources[source.URL]; exists {
			if source.LastUpdated == "" {
				source.LastUpdated = previous.LastUpdated
			}
			if source.LastError == "" {
				source.LastError = previous.LastError
			}
			if source.RuleCount == 0 {
				source.RuleCount = previous.RuleCount
			}
		}
		next[source.URL] = source
	}

	u.mu.Lock()
	old := make(map[string]Source, len(u.sources))
	for sourceURL, source := range u.sources {
		old[sourceURL] = source
	}
	u.sources = next
	u.mu.Unlock()
	// Rules of removed or disabled sources stop matching immediately.
	for sourceURL := range old {
		if _, exists := next[sourceURL]; !exists {
			u.store.RemoveRemote(sourceURL)
		}
	}
	for sourceURL, source := range next {
		if !source.Enabled {
			u.store.RemoveRemote(sourceURL)
		}
	}
}

func (u *Updater) Sources() []Source {
	u.mu.RLock()
	defer u.mu.RUnlock()
	result := make([]Source, 0, len(u.sources))
	for _, source := range u.sources {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result
}

// RefreshDue downloads enabled sources whose rules are not loaded yet (new,
// re-enabled or previously failed) or whose refresh interval has elapsed.
func (u *Updater) RefreshDue(ctx context.Context) {
	u.refreshDue(ctx, false)
}

// Run refreshes every enabled source once, then keeps them up to date until
// ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	u.refreshDue(ctx, true)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.refreshDue(ctx, false)
		}
	}
}

func (u *Updater) refreshDue(ctx context.Context, force bool) {
	sources := u.Sources()
	now := time.Now()
	for _, source := range sources {
		if !source.Enabled {
			continue
		}
		lastUpdated, _ := time.Parse(time.RFC3339, source.LastUpdated)
		loaded := u.store.HasRemote(source.URL)
		if !force && loaded && now.Before(lastUpdated.Add(time.Duration(source.IntervalMinutes)*time.Minute)) {
			continue
		}
		u.refreshOne(ctx, source)
	}
}

func (u *Updater) refreshOne(ctx context.Context, source Source) {
	entries, err := downloadRules(ctx, u.client, source.URL)
	u.mu.Lock()
	current, exists := u.sources[source.URL]
	if !exists {
		u.mu.Unlock()
		return
	}
	if err != nil {
		current.LastError = err.Error()
		if !u.store.HasRemote(source.URL) {
			current.RuleCount = 0 // nothing from this source is active
		}
	} else {
		current.LastUpdated = time.Now().Format(time.RFC3339)
		current.LastError = ""
		current.RuleCount = len(entries)
	}
	u.sources[source.URL] = current
	u.mu.Unlock()
	if err == nil && current.Enabled {
		u.store.SetRemote(source.URL, entries)
	}
}

func downloadRules(ctx context.Context, client *http.Client, rawURL string) ([]Entry, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("rule source must be an http or https URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "DNSentry/0.1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("rule source returned HTTP %d", response.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(response.Body, 20<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	entries := make([]Entry, 0)
	for scanner.Scan() {
		entry, _, ok := parseRule(scanner.Text())
		if ok {
			entry.Source = rawURL
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Store) SetRemote(source string, entries []Entry) {
	s.replaceRemote(source, entries)
}

func (s *Store) RemoveRemote(source string) {
	s.removeRemote(source)
}

// HasRemote reports whether rules from source are currently loaded.
func (s *Store) HasRemote(source string) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	_, ok := s.remoteEntries[source]
	return ok
}

type ruleCandidate struct {
	rule  parsedRule
	local bool
}

func preferRule(current, next ruleCandidate) ruleCandidate {
	if current.local != next.local {
		if next.local {
			return next
		}
		return current
	}
	if current.rule.action == ActionAllow && next.rule.action == ActionBlock {
		return current
	}
	if current.rule.action == ActionBlock && next.rule.action == ActionAllow {
		return next
	}
	return next
}

func parsedRuleFromEntry(entry Entry) parsedRule {
	parsed := parsedRule{action: entry.Action}
	if entry.IP != "" {
		parsed.ip = net.ParseIP(entry.IP)
	}
	return parsed
}
