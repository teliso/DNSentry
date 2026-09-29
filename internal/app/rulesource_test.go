package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "VigorDNS/0.1" {
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
		remoteAction RuleAction
		want         RuleAction
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

			store := NewRuleStore(file)
			if err := store.Reload(); err != nil {
				t.Fatal(err)
			}
			store.SetRemote("https://rules.example/filters", []RuleEntry{{Domain: "conflict.example.com", Action: test.remoteAction}})
			if action, _, ok := store.Match("conflict.example.com"); !ok || action != test.want {
				t.Fatalf("expected %s to override remote %s, got %q, %v", test.want, test.remoteAction, action, ok)
			}
		})
	}
}
func TestUpstreamPoolMarksFailedServers(t *testing.T) {
	pool := NewUpstreamPool([]string{"one:53", "two:53"})
	pool.RecordFailure("one:53")
	pool.RecordFailure("one:53")
	pool.RecordFailure("one:53")
	candidates := pool.Candidates()
	if len(candidates) != 1 || candidates[0] != "two:53" {
		t.Fatalf("expected failed upstream to be skipped, got %#v", candidates)
	}
	pool.RecordSuccess("one:53", 15*time.Millisecond)
	if health := pool.Health()[0]; !health.Healthy || health.Failures != 0 || health.LatencyMS != 15 {
		t.Fatalf("expected recovered upstream, got %#v", health)
	}
}
