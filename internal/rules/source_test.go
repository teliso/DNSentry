package rules

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
