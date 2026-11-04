package app

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/teliso/DNSentry/internal/rules"
)

func TestRuleEndpoints(t *testing.T) {
	api := newConfigTestAPI(t)

	if response := callAPI(t, api, http.MethodPost, "/api/rules", map[string]string{"domain": "||Ads.Example^", "action": "block"}); response.Code != http.StatusCreated {
		t.Fatalf("add = %d %s", response.Code, response.Body)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/rules", map[string]string{"domain": "ads.example", "action": "block"}); response.Code != http.StatusConflict {
		t.Fatalf("duplicate add = %d", response.Code)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/rules", map[string]string{"domain": "bad domain", "action": "block"}); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid add = %d", response.Code)
	}

	var page rules.Page
	if err := json.Unmarshal(callAPI(t, api, http.MethodGet, "/api/rules?search=ads&limit=10", nil).Body.Bytes(), &page); err != nil || page.Total != 1 {
		t.Fatalf("list = %#v %v", page, err)
	}

	var check rules.Check
	if err := json.Unmarshal(callAPI(t, api, http.MethodGet, "/api/rules/check?domain=x.ads.example", nil).Body.Bytes(), &check); err != nil || check.Rule == nil || check.Rule.Domain != "ads.example" {
		t.Fatalf("check = %#v %v", check, err)
	}

	text := "! mine\n@@||ads.example^\nnot a rule\n"
	response := callAPI(t, api, http.MethodPut, "/api/rules/local", map[string]string{"text": text})
	var summary rules.LocalSummary
	if err := json.Unmarshal(response.Body.Bytes(), &summary); err != nil || summary.Rules != 1 || summary.Ignored != 1 {
		t.Fatalf("put local = %d %s", response.Code, response.Body)
	}
	if !strings.Contains(callAPI(t, api, http.MethodGet, "/api/rules/local", nil).Body.String(), "not a rule") {
		t.Fatal("local text should be returned verbatim")
	}
	if rule, _ := api.rules.Match("ads.example"); rule.Action != rules.ActionAllow {
		t.Fatalf("edited rules not active: %#v", rule)
	}
	if response := callAPI(t, api, http.MethodDelete, "/api/rules?domain=missing.example&action=block", nil); response.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", response.Code)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/sources/refresh", map[string]string{"url": "https://unknown.example/list"}); response.Code != http.StatusNotFound {
		t.Fatalf("refresh unknown source = %d", response.Code)
	}
	if response := callAPI(t, api, http.MethodPut, "/api/sources", []rules.Source{{URL: "ftp://bad"}}); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid source = %d", response.Code)
	}
}

func TestLegacySourceStatusInConfigIsIgnored(t *testing.T) {
	t.Chdir(t.TempDir())
	config := testConfig()
	if err := saveConfig(config); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(data), "rules:\n", "rules:\n    sources:\n        - url: https://lists.example/ads.txt\n          enabled: true\n          interval_minutes: 60\n          last_updated: \"2026-01-01T00:00:00Z\"\n          rule_count: 42\n", 1)
	if legacy == string(data) {
		t.Fatal("test setup: rules section not found")
	}
	if err := os.WriteFile(configPath(), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig()
	if err != nil || len(loaded.RuleSources) != 1 || loaded.RuleSources[0].RuleCount != 0 {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
	if err := saveConfig(loaded); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(configPath())
	if strings.Contains(string(data), "rule_count") || strings.Contains(string(data), "last_updated") {
		t.Fatalf("runtime state was written to the config:\n%s", data)
	}
}
