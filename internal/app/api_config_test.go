package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

func newConfigTestAPI(t *testing.T) *API {
	t.Helper()
	t.Chdir(t.TempDir())
	config := testConfig()
	if err := os.MkdirAll(filepath.Dir(config.RulesFile), 0755); err != nil {
		t.Fatal(err)
	}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(validated); err != nil {
		t.Fatal(err)
	}
	server := &DNSServer{
		config:        validated,
		rules:         rules.NewStore(validated.RulesFile),
		cache:         cache.New(validated.CacheSize, validated.CacheEnabled),
		logs:          querylog.New(10),
		client:        &dns.Client{Net: "udp", Timeout: upstreamTimeout(validated.UpstreamTimeout)},
		pool:          NewUpstreamPool(validated.Upstreams),
		fallbackPool:  NewUpstreamPool(validated.FallbackUpstreams),
		dnssecCacheOK: make(map[string]struct{}),
	}
	server.configureAccess(validated.Access)
	return newAPI(t.Context(), "", server, rules.NewUpdater(server.rules, nil), nil)
}

func callAPI(t *testing.T, api *API, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, "http://127.0.0.1"+path, reader)
	request.RemoteAddr = "127.0.0.1:4000"
	request.Header.Set("Origin", "http://127.0.0.1")
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	return recorder
}

func TestConfigUpdateAppliesRuntimeSettingsAlongsideRestartOnlyChanges(t *testing.T) {
	api := newConfigTestAPI(t)
	next := api.configResponse()
	next.DNSListens = []string{":25353"}
	next.Upstreams = []string{"9.9.9.9:53"}

	if response := callAPI(t, api, http.MethodPut, "/api/config", next); response.Code != http.StatusOK {
		t.Fatalf("PUT /config = %d %s", response.Code, response.Body)
	}
	running := api.resolver.configSnapshot()
	if running.Upstreams[0] != "9.9.9.9:53" {
		t.Fatalf("runtime setting was not applied: %v", running.Upstreams)
	}
	if running.DNSListens[0] != ":15353" {
		t.Fatalf("running listeners must not change before a restart: %v", running.DNSListens)
	}
	var saved Config
	if err := json.Unmarshal(callAPI(t, api, http.MethodGet, "/api/config", nil).Body.Bytes(), &saved); err != nil || saved.DNSListens[0] != ":25353" {
		t.Fatalf("GET /config should return the saved listeners, got %v (%v)", saved.DNSListens, err)
	}
	if !strings.Contains(callAPI(t, api, http.MethodGet, "/api/status", nil).Body.String(), `"restart_required":true`) {
		t.Fatal("status should report the pending restart")
	}
	if loaded, err := loadConfig(); err != nil || loaded.DNSListens[0] != ":25353" {
		t.Fatalf("listen change was not persisted: %v %v", loaded, err)
	}
}

func TestSourceUpdateKeepsPendingConfigAndConfigUpdateKeepsSources(t *testing.T) {
	api := newConfigTestAPI(t)
	stale := api.configResponse() // form loaded before the source was added

	next := api.configResponse()
	next.DNSListens = []string{":25353"}
	if response := callAPI(t, api, http.MethodPut, "/api/config", next); response.Code != http.StatusOK {
		t.Fatalf("PUT /config = %d %s", response.Code, response.Body)
	}
	sources := []rules.Source{{URL: "http://127.0.0.1:1/list.txt", Enabled: false, IntervalMinutes: 60}}
	if response := callAPI(t, api, http.MethodPut, "/api/sources", sources); response.Code != http.StatusOK {
		t.Fatalf("PUT /sources = %d %s", response.Code, response.Body)
	}
	if loaded, err := loadConfig(); err != nil || loaded.DNSListens[0] != ":25353" {
		t.Fatalf("saving sources overwrote the pending listen change: %v %v", loaded, err)
	}

	stale.DNSListens = []string{":25353"}
	stale.CacheTTLMin = 60
	if response := callAPI(t, api, http.MethodPut, "/api/config", stale); response.Code != http.StatusOK {
		t.Fatalf("PUT /config = %d %s", response.Code, response.Body)
	}
	if got := api.updater.Sources(); len(got) != 1 {
		t.Fatalf("saving a stale config form removed rule sources: %v", got)
	}
	if loaded, err := loadConfig(); err != nil || len(loaded.RuleSources) != 1 {
		t.Fatalf("rule source missing from saved config: %v %v", loaded, err)
	}
}

func TestConfigUpdateRejectsOversizedBody(t *testing.T) {
	api := newConfigTestAPI(t)
	request := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/config", bytes.NewReader(bytes.Repeat([]byte{' '}, maxJSONBodyBytes+1)))
	request.RemoteAddr = "127.0.0.1:4000"
	request.Header.Set("Origin", "http://127.0.0.1")
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", recorder.Code)
	}
}
