package app

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/rules"
	"gopkg.in/yaml.v3"
)

func TestYAMLConfigRoundTrip(t *testing.T) {
	original := &Config{
		DNSListen:             ":15353",
		DNSListens:            []string{":15353", "127.0.0.1:15354"},
		HTTPListen:            ":18080",
		Upstreams:             []string{"1.1.1.1:53", "tls://dns.google:853"},
		FallbackUpstreams:     []string{"https://backup.example/dns-query"},
		UpstreamMode:          upstreamModeParallel,
		BlockingMode:          "nxdomain",
		EnableDNSSEC:          true,
		RulesFile:             "data/rules.txt",
		CacheSize:             2048,
		QueryLogSize:          200,
		QueryLogEnabled:       true,
		QueryLogFile:          "data/querylog",
		QueryLogRetentionDays: 30,
		CacheTTLMin:           30,
		CacheTTLMax:           86400,
		OptimisticCache:       true,
		OptimisticAnswerTTL:   10,
		OptimisticMaxAge:      300,
		RuleSources:           []rules.Source{{URL: "https://example.com/rules.txt", Enabled: true, IntervalMinutes: 360}},
	}
	data, err := yaml.Marshal(newYAMLConfig(original))
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(yamlConfig)
	if err := yaml.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	actual := decoded.toConfig()
	if actual.DNSListen != original.DNSListen || !slices.Equal(actual.DNSListens, original.DNSListens) || actual.HTTPListen != original.HTTPListen || actual.UpstreamMode != original.UpstreamMode || !slices.Equal(actual.FallbackUpstreams, original.FallbackUpstreams) || actual.CacheTTLMin != original.CacheTTLMin || !actual.EnableDNSSEC || !actual.OptimisticCache || actual.OptimisticAnswerTTL != original.OptimisticAnswerTTL || actual.OptimisticMaxAge != original.OptimisticMaxAge || actual.QueryLogEnabled != original.QueryLogEnabled || actual.QueryLogFile != original.QueryLogFile || actual.QueryLogRetentionDays != original.QueryLogRetentionDays || len(actual.RuleSources) != 1 {
		t.Fatalf("config did not round-trip: %#v", actual)
	}
}

func TestLegacyYAMLDNSListenPopulatesDNSListens(t *testing.T) {
	var fileConfig yamlConfig
	if err := yaml.Unmarshal([]byte("version: 1\ndns:\n  listen: ':15353'\n  upstreams:\n    - '1.1.1.1:53'\nweb:\n  listen: ':18080'\nrules:\n  local_file: data/rules.txt\n"), &fileConfig); err != nil {
		t.Fatal(err)
	}
	validated, err := validateConfig(fileConfig.toConfig())
	if err != nil {
		t.Fatal(err)
	}
	if validated.DNSListen != ":15353" || !slices.Equal(validated.DNSListens, []string{":15353"}) {
		t.Fatalf("legacy DNS listen was not normalized: %#v", validated)
	}
}

func TestDNSListenValidationDeduplicatesAndLimitsAddresses(t *testing.T) {
	config := testConfig()
	config.DNSListens = []string{" :15353 ", ":15353", "127.0.0.1:15354"}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(validated.DNSListens, []string{":15353", "127.0.0.1:15354"}) || validated.DNSListen != ":15353" {
		t.Fatalf("unexpected normalized DNS listeners: %#v", validated)
	}
	config = testConfig()
	config.DNSListens = make([]string, maxConfiguredListens+1)
	for index := range config.DNSListens {
		config.DNSListens[index] = fmt.Sprintf("127.0.0.1:%d", 20000+index)
	}
	if _, err := validateConfig(config); err == nil {
		t.Fatal("accepted more than the maximum number of DNS listeners")
	}
}

func TestYAMLCacheDefaultsToEnabled(t *testing.T) {
	var config yamlConfig
	if err := yaml.Unmarshal([]byte("version: 1\ndns:\n  listen: ':15353'\nweb:\n  listen: ':18080'\nrules:\n  local_file: data/rules.txt\n"), &config); err != nil {
		t.Fatal(err)
	}
	if !config.toConfig().CacheEnabled {
		t.Fatal("cache should default to enabled when omitted")
	}
	defaults := config.toConfig()
	if defaults.QueryLogEnabled || defaults.QueryLogFile != filepath.Join("data", "querylog") || defaults.QueryLogRetentionDays != 7 {
		t.Fatalf("unexpected query-log defaults: %#v", defaults)
	}
}

func testConfig() *Config {
	return &Config{
		DNSListen:           ":15353",
		HTTPListen:          "127.0.0.1:18080",
		Upstreams:           []string{"1.1.1.1:53"},
		RulesFile:           "data/rules.txt",
		CacheEnabled:        true,
		CacheSize:           1 << 20,
		CacheTTLMin:         30,
		CacheTTLMax:         86400,
		BlockingMode:        "custom_ip",
		BlockingIPv4:        "192.0.2.1",
		BlockingIPv6:        "2001:db8::1",
		OptimisticCache:     true,
		OptimisticAnswerTTL: 30,
		OptimisticMaxAge:    300,
	}
}

func TestSaveConfigAtomicRoundTrip(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporaryDirectory := t.TempDir()
	if err := os.Chdir(temporaryDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })

	original := testConfig()
	if err := saveConfig(original); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configPath()); err != nil {
		t.Fatalf("config was not created: %v", err)
	}

	loaded, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DNSListen != original.DNSListen || loaded.HTTPListen != original.HTTPListen || loaded.CacheSize != original.CacheSize || loaded.CacheTTLMin != original.CacheTTLMin || loaded.CacheTTLMax != original.CacheTTLMax || loaded.BlockingIPv4 != original.BlockingIPv4 || loaded.BlockingIPv6 != original.BlockingIPv6 || len(loaded.Upstreams) != 1 || loaded.Upstreams[0] != original.Upstreams[0] {
		t.Fatalf("config did not round-trip: %#v", loaded)
	}

	updated := *original
	updated.CacheSize++
	if err := saveConfig(&updated); err != nil {
		t.Fatal(err)
	}
	updatedData, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatal(err)
	}
	var decoded yamlConfig
	if err := yaml.Unmarshal(updatedData, &decoded); err != nil {
		t.Fatalf("replacement is not valid YAML: %v", err)
	}
	if decoded.Cache.Size != updated.CacheSize {
		t.Fatalf("replacement was not committed: got %d, want %d", decoded.Cache.Size, updated.CacheSize)
	}
	id, ok := previousConfigVersionID()
	if !ok {
		t.Fatal("the replaced configuration was not kept in the history")
	}
	previous, err := loadConfigVersion(id)
	if err != nil {
		t.Fatalf("previous configuration was not readable: %v", err)
	}
	if previous.CacheSize != original.CacheSize {
		t.Fatalf("previous configuration has the wrong content: got %d, want %d", previous.CacheSize, original.CacheSize)
	}

	entries, err := os.ReadDir(filepath.Dir(configPath()))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".config.yaml.tmp-") {
			t.Fatalf("temporary config was not cleaned up: %s", entry.Name())
		}
	}
}

func TestSaveConfigSerializesConcurrentWrites(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporaryDirectory := t.TempDir()
	if err := os.Chdir(temporaryDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })

	errors := make(chan error, 20)
	for index := 0; index < cap(errors); index++ {
		go func(index int) {
			config := testConfig()
			config.CacheSize += index
			errors <- saveConfig(config)
		}(index)
	}
	for index := 0; index < cap(errors); index++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadConfig(); err != nil {
		t.Fatalf("concurrent saves produced an invalid config: %v", err)
	}
}

func TestValidateUpstreamAcceptsDoH3(t *testing.T) {
	validated, err := validateUpstream("h3://dns.example/dns-query", false)
	if err != nil || validated != "h3://dns.example/dns-query" {
		t.Fatalf("DoH3 upstream validation = %q, %v", validated, err)
	}
}

func TestValidateConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"negative cache size", func(config *Config) { config.CacheSize = -1 }},
		{"inverted cache TTL", func(config *Config) { config.CacheTTLMin = 60; config.CacheTTLMax = 30 }},
		{"missing upstream", func(config *Config) { config.Upstreams = nil }},
		{"empty upstream", func(config *Config) { config.Upstreams = []string{""} }},
		{"invalid listen address", func(config *Config) { config.DNSListen = "not-an-address" }},
		{"invalid upstream address", func(config *Config) { config.Upstreams = []string{"https://"} }},
		{"invalid fallback upstream address", func(config *Config) { config.FallbackUpstreams = []string{"h3://"} }},
		{"IPv6 used as custom IPv4", func(config *Config) { config.BlockingIPv4 = "2001:db8::1" }},
		{"IPv4 used as custom IPv6", func(config *Config) { config.BlockingIPv6 = "192.0.2.1" }},
		{"invalid upstream mode", func(config *Config) { config.UpstreamMode = "race_everything" }},
		{"negative client rate limit", func(config *Config) { config.Access.ClientRateLimitQPS = -1 }},
		{"invalid allowed client", func(config *Config) { config.Access.AllowedClients = []string{"not-a-client"} }},
		{"optimistic TTL exceeds age", func(config *Config) { config.OptimisticAnswerTTL = 301; config.OptimisticMaxAge = 300 }},
		{"query log retention too short", func(config *Config) { config.QueryLogRetentionDays = -1 }},
		{"query log retention too long", func(config *Config) { config.QueryLogRetentionDays = 366 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			test.modify(config)
			if _, err := validateConfig(config); err == nil {
				t.Fatal("validateConfig accepted an invalid configuration")
			}
		})
	}
}

func TestValidateConfigClearsDisabledListenerAddresses(t *testing.T) {
	config := testConfig()
	config.Encryption = EncryptionConfig{
		Enabled:    false,
		DoTListen:  "127.0.0.1:8853",
		DoHListen:  "127.0.0.1:8443",
		DoH3Listen: "127.0.0.1:8444",
		DoQListen:  "127.0.0.1:784",
		DNSCrypt: DNSCryptConfig{
			Enabled: false,
			Listen:  "127.0.0.1:5443",
		},
	}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Encryption.DoTListen != "" || validated.Encryption.DoHListen != "" || validated.Encryption.DoH3Listen != "" || validated.Encryption.DoQListen != "" || validated.Encryption.DNSCrypt.Listen != "" {
		t.Fatalf("disabled listener addresses were retained: %#v", validated.Encryption)
	}
}

func TestValidateConfigAppliesExistingDefaults(t *testing.T) {
	config := testConfig()
	config.Upstreams = []string{"1.1.1.1"}
	config.BootstrapDNS = nil
	config.UpstreamTimeout = 0
	config.CacheSize = 0
	config.BlockingMode = ""
	config.BlockingIPv4 = ""
	config.BlockingIPv6 = ""
	config.OptimisticAnswerTTL = 0
	config.OptimisticMaxAge = 0
	config.BlockedResponseTTL = 0

	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if validated.UpstreamTimeout != 4 || validated.UpstreamMode != upstreamModeLoadBalance || validated.Access.MaxConcurrentQueries != 2048 || validated.CacheSize != 4<<20 || validated.QueryLogFile != filepath.Join("data", "querylog") || validated.QueryLogRetentionDays != 7 || validated.BlockingMode != "default" || validated.BlockingIPv4 != "0.0.0.0" || validated.BlockingIPv6 != "::" || validated.OptimisticAnswerTTL != cache.DefaultOptimisticAnswerTTL || validated.OptimisticMaxAge != cache.DefaultOptimisticMaxAgeSeconds || validated.BlockedResponseTTL != 10 {
		t.Fatalf("existing defaults changed: %#v", validated)
	}
	if len(validated.BootstrapDNS) != 2 || validated.Upstreams[0] != "1.1.1.1:53" {
		t.Fatalf("default or normalized upstream values changed: %#v", validated)
	}
}

func TestLoadConfigCreatesDefaultNextToConfigFile(t *testing.T) {
	dir := t.TempDir()
	previous := configFile
	configFile = filepath.Join(dir, "etc", "config.yaml")
	t.Cleanup(func() { configFile = previous })

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.RulesFile != filepath.Join(dir, "etc", "rules.txt") || config.HTTPListen != "127.0.0.1:18080" {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	if _, err := readConfig(); err != nil {
		t.Fatalf("default config is not valid on reload: %v", err)
	}
	if err := CheckConfig(); err != nil {
		t.Fatalf("CheckConfig: %v", err)
	}
}
