package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// listServer serves a rule list with an ETag and counts full downloads.
type listServer struct {
	*httptest.Server
	body      atomic.Value // string
	fail      atomic.Bool
	downloads atomic.Int32
	checks    atomic.Int32
}

func newListServer(t *testing.T, body string) *listServer {
	server := &listServer{}
	server.body.Store(body)
	server.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != userAgent {
			t.Errorf("unexpected User-Agent %q", request.Header.Get("User-Agent"))
		}
		if server.fail.Load() {
			http.Error(writer, "down", http.StatusBadGateway)
			return
		}
		server.checks.Add(1)
		body := server.body.Load().(string)
		etag := `"` + cacheKey(body) + `"`
		if request.Header.Get("If-None-Match") == etag {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		server.downloads.Add(1)
		writer.Header().Set("ETag", etag)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func newTestUpdater(t *testing.T, cacheDir string, sources ...Source) (*Store, *Updater) {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "rules.txt"))
	return store, NewUpdater(store, cacheDir, sources)
}

func TestRemoteRulesAreCachedAndRestoredAfterRestart(t *testing.T) {
	server := newListServer(t, "||ads.remote.test^\n0.0.0.0 a.test b.test\n")
	cacheDir := t.TempDir()
	source := Source{URL: server.URL, Enabled: true, IntervalMinutes: 60}

	store, updater := newTestUpdater(t, cacheDir, source)
	updater.RefreshDue(context.Background())
	if rule := mustMatch(t, store, "ads.remote.test", ActionBlock); rule.Source != server.URL {
		t.Fatalf("rule source = %q", rule.Source)
	}
	if got := updater.Sources()[0]; got.RuleCount != 3 || got.LastUpdated == "" || got.LastError != "" {
		t.Fatalf("status after download = %#v", got.SourceStatus)
	}

	// Restart while the source is unreachable: cached rules are active at once.
	server.fail.Store(true)
	store, updater = newTestUpdater(t, cacheDir, source)
	mustMatch(t, store, "b.test", ActionBlock)
	updater.RefreshDue(context.Background()) // within interval: no request
	if server.downloads.Load() != 1 {
		t.Fatalf("downloads = %d, want 1", server.downloads.Load())
	}

	// A forced refresh that fails keeps the cached rules and reports the error.
	if err := updater.StartRefresh(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !updater.Sources()[0].Updating })
	if got := updater.Sources()[0]; got.LastError == "" || got.RuleCount != 3 {
		t.Fatalf("status after failure = %#v", got.SourceStatus)
	}
	mustMatch(t, store, "ads.remote.test", ActionBlock)
}

func TestConditionalRefreshAndChangedList(t *testing.T) {
	server := newListServer(t, "||one.test^\n")
	store, updater := newTestUpdater(t, t.TempDir(), Source{URL: server.URL, Enabled: true})
	updater.RefreshDue(context.Background())

	refreshNow := func() {
		t.Helper()
		if err := updater.StartRefresh(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return !updater.Sources()[0].Updating })
	}
	refreshNow()
	if server.downloads.Load() != 1 || server.checks.Load() != 2 {
		t.Fatalf("unchanged list should be revalidated, not downloaded: downloads=%d checks=%d", server.downloads.Load(), server.checks.Load())
	}
	server.body.Store("||two.test^\n")
	refreshNow()
	mustMatch(t, store, "two.test", ActionBlock)
	if _, ok := store.Match("one.test"); ok {
		t.Fatal("rules from the previous list version are still active")
	}
}

func TestDisableEnableAndRemoveSource(t *testing.T) {
	server := newListServer(t, "||ads.remote.test^\n")
	cacheDir := t.TempDir()
	source := Source{URL: server.URL, Name: "Ads", Enabled: true}
	store, updater := newTestUpdater(t, cacheDir, source)
	updater.RefreshDue(context.Background())

	source.Enabled = false
	if err := updater.SetSources([]Source{source}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Match("ads.remote.test"); ok {
		t.Fatal("disabled source still matches")
	}
	source.Enabled = true
	if err := updater.SetSources([]Source{source}); err != nil {
		t.Fatal(err)
	}
	mustMatch(t, store, "ads.remote.test", ActionBlock) // restored from cache, no download
	if server.downloads.Load() != 1 {
		t.Fatalf("re-enabling should use the cache, downloads=%d", server.downloads.Load())
	}

	if err := updater.SetSources(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Match("ads.remote.test"); ok {
		t.Fatal("removed source still matches")
	}
	if entries, _ := os.ReadDir(cacheDir); len(entries) != 0 {
		t.Fatalf("cache of removed source was kept: %v", entries)
	}
}

func TestNormalizeSourcesRejectsInvalidConfiguration(t *testing.T) {
	for name, sources := range map[string][]Source{
		"scheme":    {{URL: "ftp://example.com/list"}},
		"duplicate": {{URL: "https://a.test/l"}, {URL: " https://a.test/l "}},
		"interval":  {{URL: "https://a.test/l", IntervalMinutes: -1}},
	} {
		if _, err := NormalizeSources(sources); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	normalized, err := NormalizeSources([]Source{{URL: " https://a.test/l ", SourceStatus: SourceStatus{RuleCount: 9}}})
	if err != nil || normalized[0].URL != "https://a.test/l" || normalized[0].IntervalMinutes != DefaultIntervalMinutes || normalized[0].RuleCount != 0 {
		t.Fatalf("normalized = %#v, %v", normalized, err)
	}
}

func TestPruneRemovesOrphanedCacheFiles(t *testing.T) {
	cacheDir := t.TempDir()
	orphan := filepath.Join(cacheDir, cacheKey("https://gone.test/list")+".rules")
	if err := os.WriteFile(orphan, []byte("||x.test^\n"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(cacheDir, "README")
	if err := os.WriteFile(unrelated, nil, 0600); err != nil {
		t.Fatal(err)
	}
	newTestUpdater(t, cacheDir)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphaned cache file was kept")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated file was removed")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
