package rules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIntervalMinutes = 360
	maxIntervalMinutes     = 30 * 24 * 60
	MaxSources             = 64
	maxSourceNameLength    = 64
	maxListBytes           = 32 << 20
	// A failing source is retried after this delay, or its interval if shorter.
	failureRetryDelay = 10 * time.Minute
	userAgent         = "DNSentry/0.1"
)

var ErrUnknownSource = errors.New("unknown rule source")

// Source is a subscribed remote rule list. Only the first four fields are
// configuration (persisted in config.yaml); SourceStatus is runtime state kept
// in the rule cache and reported by the API.
type Source struct {
	URL             string `json:"url" yaml:"url"`
	Name            string `json:"name,omitempty" yaml:"name,omitempty"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	IntervalMinutes int    `json:"interval_minutes" yaml:"interval_minutes"`
	SourceStatus    `yaml:"-"`
}

// SourceStatus is the refresh state of a Source.
type SourceStatus struct {
	LastUpdated string `json:"last_updated,omitempty"` // last download with new content
	LastChecked string `json:"last_checked,omitempty"` // last successful check, including "not modified"
	LastError   string `json:"last_error,omitempty"`   // error of the last attempt, if it failed
	RuleCount   int    `json:"rule_count"`             // rules loaded from this source
	Updating    bool   `json:"updating,omitempty"`
}

// NormalizeSources validates source configuration, trims fields, applies the
// default interval and drops runtime state.
func NormalizeSources(sources []Source) ([]Source, error) {
	if len(sources) > MaxSources {
		return nil, fmt.Errorf("at most %d rule sources are supported", MaxSources)
	}
	seen := make(map[string]bool, len(sources))
	result := make([]Source, 0, len(sources))
	for index, source := range sources {
		source.URL = strings.TrimSpace(source.URL)
		source.Name = strings.TrimSpace(source.Name)
		parsed, err := url.Parse(source.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("rule source %d: URL must be an http or https URL", index+1)
		}
		if seen[source.URL] {
			return nil, fmt.Errorf("rule source %s is listed twice", source.URL)
		}
		seen[source.URL] = true
		if len([]rune(source.Name)) > maxSourceNameLength {
			return nil, fmt.Errorf("rule source %d: name must be at most %d characters", index+1, maxSourceNameLength)
		}
		if source.IntervalMinutes == 0 {
			source.IntervalMinutes = DefaultIntervalMinutes
		}
		if source.IntervalMinutes < 1 || source.IntervalMinutes > maxIntervalMinutes {
			return nil, fmt.Errorf("rule source %d: interval must be between 1 and %d minutes", index+1, maxIntervalMinutes)
		}
		source.SourceStatus = SourceStatus{}
		result = append(result, source)
	}
	return result, nil
}

// sourceState is the updater's private view of one source.
type sourceState struct {
	status       SourceStatus
	etag         string
	lastModified string
	lastAttempt  time.Time
}

// Updater keeps remote rule lists loaded into a Store: it restores them from
// the on-disk cache, downloads due lists (with conditional requests) and
// unloads lists that are removed or disabled.
type Updater struct {
	store  *Store
	cache  sourceCache
	client *http.Client

	mu      sync.Mutex
	sources []Source // configuration, in user order
	state   map[string]*sourceState
}

// NewUpdater loads the cached rules of every enabled source into store.
// cacheDir may be empty to disable the on-disk cache. Invalid source
// configuration is rejected by NormalizeSources; entries it would reject are
// skipped here.
func NewUpdater(store *Store, cacheDir string, sources []Source) *Updater {
	updater := &Updater{
		store:  store,
		cache:  sourceCache{dir: cacheDir},
		client: &http.Client{Timeout: 60 * time.Second},
		state:  make(map[string]*sourceState),
	}
	if normalized, err := NormalizeSources(sources); err == nil {
		sources = normalized
	} else {
		sources = nil
	}
	_ = updater.SetSources(sources)
	urls := make([]string, 0, len(sources))
	for _, source := range sources {
		urls = append(urls, source.URL)
	}
	updater.cache.prune(urls)
	return updater
}

// SetSources replaces the source configuration. Removed sources are unloaded
// and their cache deleted; disabled ones are unloaded; enabled ones that are
// not loaded yet are restored from the cache.
func (u *Updater) SetSources(sources []Source) error {
	sources, err := NormalizeSources(sources)
	if err != nil {
		return err
	}
	u.mu.Lock()
	next := make(map[string]bool, len(sources))
	for _, source := range sources {
		next[source.URL] = true
	}
	var removed []string
	for url := range u.state {
		if !next[url] {
			removed = append(removed, url)
			delete(u.state, url)
		}
	}
	var toRestore []string
	for _, source := range sources {
		if _, exists := u.state[source.URL]; !exists {
			state := &sourceState{}
			if cached, ok := u.cache.loadState(source.URL); ok {
				state.status = SourceStatus{LastUpdated: cached.LastUpdated, LastChecked: cached.LastChecked, LastError: cached.LastError}
				state.etag, state.lastModified = cached.ETag, cached.LastModified
			}
			u.state[source.URL] = state
		}
		if source.Enabled && !u.store.HasRemote(source.URL) {
			toRestore = append(toRestore, source.URL)
		}
	}
	u.sources = sources
	u.mu.Unlock()

	for _, url := range removed {
		u.store.RemoveRemote(url)
		u.cache.remove(url)
	}
	for _, source := range sources {
		if !source.Enabled {
			u.store.RemoveRemote(source.URL)
		}
	}
	for _, url := range toRestore {
		entries, err := u.cache.loadRules(url)
		if err != nil {
			continue
		}
		u.mu.Lock()
		if u.isEnabledLocked(url) {
			u.store.SetRemote(url, entries)
		}
		u.mu.Unlock()
	}
	return nil
}

func (u *Updater) isEnabledLocked(url string) bool {
	for _, source := range u.sources {
		if source.URL == url {
			return source.Enabled
		}
	}
	return false
}

// Sources returns the configured sources with their current status.
func (u *Updater) Sources() []Source {
	counts := u.store.Counts()
	u.mu.Lock()
	defer u.mu.Unlock()
	result := make([]Source, len(u.sources))
	for index, source := range u.sources {
		if state := u.state[source.URL]; state != nil {
			source.SourceStatus = state.status
		}
		source.RuleCount = counts[source.URL]
		result[index] = source
	}
	return result
}

// Run keeps enabled sources up to date until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	u.RefreshDue(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.RefreshDue(ctx)
		}
	}
}

// RefreshDue refreshes enabled sources that are not loaded or whose interval
// has elapsed. Sources whose last attempt failed wait failureRetryDelay.
func (u *Updater) RefreshDue(ctx context.Context) {
	now := time.Now()
	u.mu.Lock()
	var due []string
	for _, source := range u.sources {
		state := u.state[source.URL]
		if !source.Enabled || state == nil || state.status.Updating {
			continue
		}
		interval := time.Duration(source.IntervalMinutes) * time.Minute
		if state.status.LastError != "" && now.Before(state.lastAttempt.Add(min(interval, failureRetryDelay))) {
			continue
		}
		lastChecked, _ := time.Parse(time.RFC3339, state.status.LastChecked)
		if u.store.HasRemote(source.URL) && now.Before(lastChecked.Add(interval)) {
			continue
		}
		state.status.Updating = true
		due = append(due, source.URL)
	}
	u.mu.Unlock()
	for _, url := range due {
		u.refresh(ctx, url)
	}
}

// StartRefresh downloads url now, or every enabled source if url is empty,
// in the background. Sources already being refreshed are skipped.
func (u *Updater) StartRefresh(ctx context.Context, url string) error {
	u.mu.Lock()
	var targets []string
	found := false
	for _, source := range u.sources {
		if url != "" && source.URL != url {
			continue
		}
		found = true
		state := u.state[source.URL]
		if source.Enabled && state != nil && !state.status.Updating {
			state.status.Updating = true
			targets = append(targets, source.URL)
		}
	}
	u.mu.Unlock()
	if url != "" && !found {
		return ErrUnknownSource
	}
	go func() {
		for _, target := range targets {
			u.refresh(ctx, target)
		}
	}()
	return nil
}

// refresh downloads one source whose Updating flag the caller has set.
func (u *Updater) refresh(ctx context.Context, url string) {
	u.mu.Lock()
	state := u.state[url]
	if state == nil {
		u.mu.Unlock()
		return
	}
	etag, lastModified := state.etag, state.lastModified
	u.mu.Unlock()
	if !u.store.HasRemote(url) {
		// Nothing loaded to fall back on: always fetch the full list.
		etag, lastModified = "", ""
	}

	result, err := download(ctx, u.client, url, etag, lastModified)
	now := time.Now()

	u.mu.Lock()
	state = u.state[url]
	if state == nil { // removed while downloading
		u.mu.Unlock()
		return
	}
	state.status.Updating = false
	if ctx.Err() != nil { // shutting down: not a failure of the source
		u.mu.Unlock()
		return
	}
	state.lastAttempt = now
	switch {
	case err != nil:
		state.status.LastError = err.Error()
	case result.notModified:
		state.status.LastError = ""
		state.status.LastChecked = now.Format(time.RFC3339)
	default:
		state.status.LastError = ""
		state.status.LastChecked = now.Format(time.RFC3339)
		state.status.LastUpdated = state.status.LastChecked
		state.etag, state.lastModified = result.etag, result.lastModified
	}
	persisted := cacheState{
		URL:          url,
		LastUpdated:  state.status.LastUpdated,
		LastChecked:  state.status.LastChecked,
		LastError:    state.status.LastError,
		ETag:         state.etag,
		LastModified: state.lastModified,
	}
	if err == nil && !result.notModified && u.isEnabledLocked(url) {
		u.store.SetRemote(url, result.entries)
	}
	u.mu.Unlock()

	if err == nil && !result.notModified {
		if saveErr := u.cache.saveRules(url, result.entries); saveErr != nil {
			persisted.ETag, persisted.LastModified = "", "" // force a full download next time
		}
	}
	_ = u.cache.saveState(persisted)
}

type downloadResult struct {
	entries      []Entry
	notModified  bool
	etag         string
	lastModified string
}

func download(ctx context.Context, client *http.Client, rawURL, etag, lastModified string) (downloadResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return downloadResult{}, err
	}
	request.Header.Set("User-Agent", userAgent)
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		request.Header.Set("If-Modified-Since", lastModified)
	}
	response, err := client.Do(request)
	if err != nil {
		return downloadResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified && (etag != "" || lastModified != "") {
		return downloadResult{notModified: true}, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return downloadResult{}, fmt.Errorf("rule source returned HTTP %d", response.StatusCode)
	}

	body := &io.LimitedReader{R: response.Body, N: maxListBytes + 1}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var entries []Entry
	for scanner.Scan() {
		for _, entry := range ParseLine(scanner.Text()) {
			entry.Source = rawURL
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return downloadResult{}, err
	}
	if body.N <= 0 {
		return downloadResult{}, fmt.Errorf("rule list exceeds %d MB", maxListBytes>>20)
	}
	return downloadResult{
		entries:      entries,
		etag:         response.Header.Get("ETag"),
		lastModified: response.Header.Get("Last-Modified"),
	}, nil
}
