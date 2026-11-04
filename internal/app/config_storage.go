package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/teliso/DNSentry/internal/access"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/fsutil"
)

const (
	maxConfiguredUpstreams = 32
	defaultQueryLogSize    = 1000
)

// defaultQueryLogFile is where the query log goes unless configured: next to
// the configuration file.
func defaultQueryLogFile() string { return filepath.Join(filepath.Dir(configPath()), "querylog") }

// configFile is the YAML configuration path; SetupPaths may override it once at startup.
var configFile = filepath.Join("data", "config.yaml")

// SetupPaths decides where DNSentry keeps its files; call it before Run or
// CheckConfig. dataDir, when given, becomes the working directory (created if
// needed), so every relative path in the configuration lives inside it, and
// the configuration defaults to <dataDir>/config.yaml. configPath, when given,
// names the configuration file explicitly (relative to the directory the
// program was started in). With neither, the configuration is data/config.yaml
// under the current directory.
func SetupPaths(configPath, dataDir string) error {
	if configPath != "" {
		absolute, err := filepath.Abs(configPath)
		if err != nil {
			return err
		}
		configFile = absolute
	}
	if dataDir == "" {
		return nil
	}
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chdir(absolute); err != nil {
		return fmt.Errorf("use data directory: %w", err)
	}
	if configPath == "" {
		configFile = filepath.Join(absolute, "config.yaml")
	}
	return nil
}

func configPath() string { return configFile }

// defaultConfig is written on first start when no configuration exists. Data
// files are placed next to the configuration file. DNSENTRY_DNS_LISTEN and
// DNSENTRY_WEB_LISTEN override the listen addresses of this initial
// configuration only, which suits container images.
func defaultConfig() *Config {
	dir := filepath.Dir(configPath())
	return &Config{
		DNSListens:            []string{envOr("DNSENTRY_DNS_LISTEN", ":15353")},
		HTTPListen:            envOr("DNSENTRY_WEB_LISTEN", "127.0.0.1:18080"),
		Upstreams:             []string{"1.1.1.1:53", "8.8.8.8:53"},
		BootstrapDNS:          []string{"1.1.1.1:53", "8.8.8.8:53"},
		UpstreamMode:          "load_balance",
		PrivateReverse:        true,
		UpstreamTimeout:       4,
		BlockingMode:          "nxdomain",
		BlockingIPv4:          "0.0.0.0",
		BlockingIPv6:          "::",
		BlockedResponseTTL:    10,
		RulesFile:             filepath.Join(dir, "rules.txt"),
		CacheEnabled:          true,
		CacheSize:             4 << 20,
		QueryLogSize:          defaultQueryLogSize,
		QueryLogFile:          defaultQueryLogFile(),
		QueryLogRetentionDays: 7,
		Access:                access.Config{MaxConcurrentQueries: 2048},
		Encryption:            EncryptionConfig{DNSCrypt: DNSCryptConfig{ProviderName: "dnsentry", CertificateTTLHours: 24}},
	}
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// readConfig parses and validates the configuration file without side effects.
func readConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	fileConfig := new(yamlConfig)
	if err := yaml.Unmarshal(data, fileConfig); err != nil {
		return nil, fmt.Errorf("invalid YAML in %s: %w", configPath(), err)
	}
	validated, err := validateConfig(fileConfig.toConfig())
	if err != nil {
		return nil, fmt.Errorf("invalid configuration in %s: %w", configPath(), err)
	}
	return validated, nil
}

// loadConfig reads the configuration, creating a default one on first start.
func loadConfig() (*Config, error) {
	config, err := readConfig()
	if !errors.Is(err, os.ErrNotExist) {
		return config, err
	}
	config, err = validateConfig(defaultConfig())
	if err != nil {
		return nil, err
	}
	if err := saveConfig(config); err != nil {
		return nil, fmt.Errorf("create default configuration: %w", err)
	}
	slog.Info("created default configuration", "path", configPath())
	return config, nil
}

var configSaveMu sync.Mutex

func saveConfig(config *Config) error {
	configSaveMu.Lock()
	defer configSaveMu.Unlock()

	validated, err := validateConfig(config)
	if err != nil {
		return err
	}
	if _, err := prepareDNSCryptConfig(&validated.Encryption.DNSCrypt); err != nil {
		return err
	}
	data, err := yaml.Marshal(newYAMLConfig(validated))
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	path := configPath()
	// Keep the configuration being replaced as the baseline of the history when
	// this installation has none yet (it predates versioning).
	if len(configVersionIDs()) == 0 {
		if old, err := os.ReadFile(path); err == nil {
			modified := time.Now()
			if info, err := os.Stat(path); err == nil {
				modified = info.ModTime()
			}
			if err := archiveConfigVersion(old, modified); err != nil {
				slog.Warn("could not archive the previous configuration", "error", err)
			}
		}
	}
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := archiveConfigVersion(data, time.Now()); err != nil {
		slog.Warn("could not record the configuration version", "error", err)
	}
	return nil
}
