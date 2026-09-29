package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "DNSentry/0.1" {
			t.Errorf("unexpected user agent: %q", request.Header.Get("User-Agent"))
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("! comment\n||ads.remote.test^\n@@||safe.remote.test^\n"))
	}))
	defer server.Close()

	entries, err := downloadRules(t.Context(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Domain != "ads.remote.test" || entries[1].Action != ActionAllow {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestLocalRulesOverrideRemoteRules(t *testing.T) {
	for _, test := range []struct {
		name         string
		localLine    string
		remoteAction Action
		want         Action
	}{
		{name: "local block over remote allow", localLine: "||conflict.example.com^\n", remoteAction: ActionAllow, want: ActionBlock},
		{name: "local allow over remote block", localLine: "@@||conflict.example.com^\n", remoteAction: ActionBlock, want: ActionAllow},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			file := filepath.Join(directory, "rules.txt")
			if err := os.WriteFile(file, []byte(test.localLine), 0600); err != nil {
				t.Fatal(err)
			}

			store := NewStore(file)
			if err := store.Reload(); err != nil {
				t.Fatal(err)
			}
			store.SetRemote("https://rules.example/filters", []Entry{{Domain: "conflict.example.com", Action: test.remoteAction}})
			if action, _, ok := store.Match("conflict.example.com"); !ok || action != test.want {
				t.Fatalf("expected %s to override remote %s, got %q, %v", test.want, test.remoteAction, action, ok)
			}
		})
	}
}

func TestDisablingSourceRemovesItsRules(t *testing.T) {
	file := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(file)
	const url = "https://rules.example/list"
	updater := NewUpdater(store, []Source{{URL: url, Enabled: true}})
	store.SetRemote(url, []Entry{{Domain: "ads.remote.test", Action: ActionBlock, Source: url}})
	if _, _, ok := store.Match("ads.remote.test"); !ok {
		t.Fatal("expected remote rule to match")
	}

	updater.SetSources([]Source{{URL: url, Enabled: false}})
	if _, _, ok := store.Match("ads.remote.test"); ok {
		t.Fatal("disabled source should no longer match")
	}
	if store.HasRemote(url) {
		t.Fatal("disabled source should not keep loaded rules")
	}
}

func TestRefreshDueFetchesSourcesWithoutLoadedRules(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte("||ads.remote.test^\n"))
	}))
	defer server.Close()

	file := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(file)
	// A recent LastUpdated (e.g. restored from config) must not hide the fact
	// that nothing is loaded.
	updater := NewUpdater(store, []Source{{URL: server.URL, Enabled: true, IntervalMinutes: 60, LastUpdated: time.Now().Format(time.RFC3339)}})
	updater.RefreshDue(context.Background())
	if requests != 1 || !store.HasRemote(server.URL) {
		t.Fatalf("expected one download, got %d (loaded=%v)", requests, store.HasRemote(server.URL))
	}
	updater.RefreshDue(context.Background())
	if requests != 1 {
		t.Fatalf("loaded source within its interval should not be downloaded again, got %d requests", requests)
	}
}
