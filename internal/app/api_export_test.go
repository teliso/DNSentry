package app

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teliso/DNSentry/internal/querylog"
)

func TestExportLogsCSVFiltersAndNeutralisesFormulas(t *testing.T) {
	api := newConfigTestAPI(t)
	api.logs.Add(querylog.Entry{Time: "2026-01-01T00:00:00Z", Client: "192.0.2.1", Domain: "a.test", Type: "A", Action: "block", Rule: "@@||evil^"})
	api.logs.Add(querylog.Entry{Time: "2026-01-01T00:00:01Z", Client: "192.0.2.2", Domain: "b.test", Type: "A", Action: "forwarded"})

	response := callAPI(t, api, http.MethodGet, "/api/logs/export?action=block", nil)
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment;") || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export = %d %v", response.Code, response.Header())
	}
	rows, err := csv.NewReader(response.Body).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][2] != "a.test" {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if rows[1][7] != "'@@||evil^" {
		t.Fatalf("a cell starting with @ was not neutralised: %q", rows[1][7])
	}
	if response := callAPI(t, api, http.MethodGet, "/api/logs/export?format=json", nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "b.test") {
		t.Fatalf("json export = %d %s", response.Code, response.Body)
	}
	if response := callAPI(t, api, http.MethodGet, "/api/logs/export?format=xml", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("bad format = %d", response.Code)
	}
}

func TestConfigExportAndImportRoundTrip(t *testing.T) {
	api := newConfigTestAPI(t)
	exported := callAPI(t, api, http.MethodGet, "/api/config/export", nil)
	if exported.Code != http.StatusOK || !strings.Contains(exported.Body.String(), "upstreams") {
		t.Fatalf("export = %d %s", exported.Code, exported.Body)
	}
	changed := strings.Replace(exported.Body.String(), "block_aaaa: false", "block_aaaa: true", 1)
	if changed == exported.Body.String() {
		t.Fatal("test setup: block_aaaa not found in the exported file")
	}
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/config/import", bytes.NewBufferString(body))
		request.RemoteAddr = "127.0.0.1:4000"
		request.Header.Set("Origin", "http://127.0.0.1")
		recorder := httptest.NewRecorder()
		api.handle(recorder, request)
		return recorder
	}
	if response := post(changed); response.Code != http.StatusOK {
		t.Fatalf("import = %d %s", response.Code, response.Body)
	}
	if loaded, err := loadConfig(); err != nil || !loaded.BlockAAAA {
		t.Fatalf("imported setting not saved: %v %v", loaded, err)
	}
	if !api.resolver.configSnapshot().BlockAAAA {
		t.Fatal("imported setting was not applied to the running resolver")
	}
	if versions := listConfigVersions(); len(versions) < 2 {
		t.Fatalf("import was not recorded in the history: %d", len(versions))
	}
	if response := post("dns: [not, a, map"); response.Code != http.StatusBadRequest {
		t.Fatalf("garbage import = %d", response.Code)
	}
	if response := post("version: 1\ndns:\n  listens: [':1']\n"); response.Code != http.StatusBadRequest {
		t.Fatalf("incomplete import = %d", response.Code)
	}
	if response := post(exported.Body.String()+"\nrules_dummy: 1\n"); response.Code != http.StatusOK {
		t.Fatalf("unknown keys must be ignored: %d", response.Code)
	}
}
