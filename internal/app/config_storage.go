package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/fsutil"
)

const maxConfiguredUpstreams = 32

// configFile is the YAML configuration path; Run may override it once at startup.
var configFile = filepath.Join("data", "config.yaml")

func configPath() string { return configFile }

func configBackupPath() string { return configPath() + ".bak" }

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
		UpstreamTimeout:       4,
		BlockingMode:          "nxdomain",
		BlockingIPv4:          "0.0.0.0",
		BlockingIPv6:          "::",
		BlockedResponseTTL:    10,
		RulesFile:             filepath.Join(dir, "rules.txt"),
		CacheEnabled:          true,
		CacheSize:             4 << 20,
		QueryLogSize:          1000,
		QueryLogFile:          filepath.Join(dir, "querylog"),
		QueryLogRetentionDays: 7,
		Access:                DNSAccessConfig{MaxConcurrentQueries: 2048},
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

func backupConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return fsutil.WriteFileAtomic(configBackupPath(), data, 0600)
}

func loadConfigBackup() (*Config, error) {
	data, err := os.ReadFile(configBackupPath())
	if err != nil {
		return nil, err
	}
	fileConfig := new(yamlConfig)
	if err := yaml.Unmarshal(data, fileConfig); err != nil {
		return nil, fmt.Errorf("invalid YAML backup: %w", err)
	}
	validated, err := validateConfig(fileConfig.toConfig())
	if err != nil {
		return nil, fmt.Errorf("invalid configuration backup: %w", err)
	}
	return validated, nil
}

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
	if err := backupConfig(path); err != nil {
		return fmt.Errorf("backup config: %w", err)
	}
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
