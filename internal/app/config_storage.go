package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/fsutil"
)

const maxConfiguredUpstreams = 32

// configFile is the YAML configuration path; Run may override it once at startup.
var configFile = filepath.Join("data", "config.yaml")

func configPath() string { return configFile }

func configBackupPath() string { return configPath() + ".bak" }

func legacyConfigPath() string { return filepath.Join(filepath.Dir(configPath()), "config.json") }

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err == nil {
		fileConfig := new(yamlConfig)
		if err := yaml.Unmarshal(data, fileConfig); err != nil {
			return nil, fmt.Errorf("invalid YAML config: %w", err)
		}
		validated, err := validateConfig(fileConfig.toConfig())
		if err != nil {
			return nil, err
		}
		return validated, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	legacyData, legacyErr := os.ReadFile(legacyConfigPath())
	if legacyErr != nil {
		if os.IsNotExist(legacyErr) {
			return nil, fmt.Errorf("neither %s nor legacy %s exists", configPath(), legacyConfigPath())
		}
		return nil, legacyErr
	}
	legacyConfig := new(Config)
	if err := json.Unmarshal(legacyData, legacyConfig); err != nil {
		return nil, fmt.Errorf("invalid legacy JSON config: %w", err)
	}
	// The original MVP measured cache_size as entry count. Migrate it to bytes.
	legacyConfig.CacheEnabled = true
	if legacyConfig.CacheSize < 65536 {
		legacyConfig.CacheSize = 4 << 20
	}
	legacyConfig, err = validateConfig(legacyConfig)
	if err != nil {
		return nil, err
	}
	if err := saveConfig(legacyConfig); err != nil {
		return nil, fmt.Errorf("could not migrate JSON config to YAML: %w", err)
	}
	fmt.Printf("Migrated %s to %s\n", legacyConfigPath(), configPath())
	return legacyConfig, nil
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
