package app

import (
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigHistoryRecordsVersionsAndChanges(t *testing.T) {
	api := newConfigTestAPI(t) // saves the initial configuration
	if versions := listConfigVersions(); len(versions) != 1 || !versions[0].Current {
		t.Fatalf("initial versions = %#v", versions)
	}

	next := api.configResponse()
	next.Upstreams = []string{"9.9.9.9:53"}
	next.BlockAAAA = true
	if response := callAPI(t, api, http.MethodPut, "/api/config", next); response.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", response.Code, response.Body)
	}
	versions := listConfigVersions()
	if len(versions) != 2 || !versions[0].Current || versions[1].Current {
		t.Fatalf("versions = %#v", versions)
	}
	changes := versions[0].Changes
	if len(changes) != 2 || changes[0] != "dns.block_aaaa" || changes[1] != "dns.upstreams" {
		t.Fatalf("changes = %v", changes)
	}
	if len(versions[1].Changes) != 0 {
		t.Fatalf("the oldest version has nothing to compare with: %v", versions[1].Changes)
	}

	// Saving identical content adds no version.
	if response := callAPI(t, api, http.MethodPut, "/api/config", api.configResponse()); response.Code != http.StatusOK {
		t.Fatalf("PUT = %d", response.Code)
	}
	if got := len(listConfigVersions()); got != 2 {
		t.Fatalf("an unchanged save created a version: %d", got)
	}
}

func TestRestoreByIDAndDefault(t *testing.T) {
	api := newConfigTestAPI(t)
	first := listConfigVersions()[0].ID
	for _, servers := range [][]string{{"9.9.9.9:53"}, {"8.8.4.4:53"}} {
		next := api.configResponse()
		next.Upstreams = servers
		if response := callAPI(t, api, http.MethodPut, "/api/config", next); response.Code != http.StatusOK {
			t.Fatalf("PUT = %d %s", response.Code, response.Body)
		}
	}

	// Default: the version before the current one.
	if response := callAPI(t, api, http.MethodPost, "/api/config/restore", nil); response.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", response.Code, response.Body)
	}
	if got := api.resolver.configSnapshot().Upstreams[0]; got != "9.9.9.9:53" {
		t.Fatalf("default restore applied %q", got)
	}
	// By id: back to the very first configuration.
	if response := callAPI(t, api, http.MethodPost, "/api/config/restore", map[string]string{"id": first}); response.Code != http.StatusOK {
		t.Fatalf("restore by id = %d %s", response.Code, response.Body)
	}
	if got := api.resolver.configSnapshot().Upstreams[0]; got != "1.1.1.1:53" {
		t.Fatalf("restore by id applied %q", got)
	}
	// Restoring is itself recorded, so it can be undone.
	if versions := listConfigVersions(); !versions[0].Current || len(versions) < 4 {
		t.Fatalf("versions after restore = %#v", versions)
	}
	for _, bad := range []string{"../../etc/passwd", "20260101T000000.000Z", "nonsense"} {
		if response := callAPI(t, api, http.MethodPost, "/api/config/restore", map[string]string{"id": bad}); response.Code != http.StatusNotFound {
			t.Errorf("restore %q = %d, want 404", bad, response.Code)
		}
	}
}

func TestConfigHistoryIsPrunedAndBaselinedForOldInstallations(t *testing.T) {
	t.Chdir(t.TempDir())
	config := testConfig()
	if err := os.MkdirAll(filepath.Dir(config.RulesFile), 0755); err != nil {
		t.Fatal(err)
	}
	// An installation from before versioning: a config file but no history.
	if err := saveConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(configHistoryDir()); err != nil {
		t.Fatal(err)
	}
	config.CacheSize++
	if err := saveConfig(config); err != nil {
		t.Fatal(err)
	}
	if versions := listConfigVersions(); len(versions) != 2 {
		t.Fatalf("the replaced file should become the baseline version: %#v", versions)
	}

	base := time.Now()
	for index := 0; index < maxConfigVersions+5; index++ {
		if err := archiveConfigVersion([]byte("version: 1\ndns:\n  n: "+time.Duration(index).String()+"\n"), base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(configVersionIDs()); got != maxConfigVersions {
		t.Fatalf("history holds %d versions, want %d", got, maxConfigVersions)
	}
}

func TestConfigChangesIgnoreMaterializedDefaults(t *testing.T) {
	t.Chdir(t.TempDir())
	// An older file that lacks keys newer versions write out explicitly.
	older := []byte("version: 1\ndns:\n  listens: [\":15353\"]\n  upstreams: [\"1.1.1.1:53\"]\nweb:\n  listen: 127.0.0.1:18080\n")
	validated, err := validateConfig(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	validated.Upstreams = []string{"1.1.1.1:53"}
	validated.DNSListens = []string{":15353"}
	validated.HTTPListen = "127.0.0.1:18080"
	validated.CacheEnabled = true
	validated.OptimisticCache = false
	validated.BlockingMode = "nxdomain"
	validated.CacheSize = 4 << 20
	validated.QueryLogRetentionDays = 7
	validated.UpstreamMode = "load_balance"
	validated.BootstrapDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
	validated.PrivateReverse = true
	validated.Encryption.DNSCrypt = DNSCryptConfig{ProviderName: "dnsentry", CertificateTTLHours: 24}
	newer, err := yaml.Marshal(newYAMLConfig(validated))
	if err != nil {
		t.Fatal(err)
	}
	if changes := configChanges(newer, older); len(changes) != 0 {
		t.Fatalf("defaults written by a newer version were reported as changes: %v", changes)
	}
	validated.BlockAAAA = true
	changed, _ := yaml.Marshal(newYAMLConfig(validated))
	if changes := configChanges(changed, older); len(changes) != 1 || changes[0] != "dns.block_aaaa" {
		t.Fatalf("changes = %v", changes)
	}
}
