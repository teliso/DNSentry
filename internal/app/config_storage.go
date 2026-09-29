package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"gopkg.in/yaml.v3"
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
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".config.yaml.bak.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if written, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	} else if written != len(data) {
		_ = temporary.Close()
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	backupPath := configBackupPath()
	if err := os.Rename(temporaryPath, backupPath); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(backupPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		if err := os.Rename(temporaryPath, backupPath); err != nil {
			return err
		}
	}
	committed = true
	return nil
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
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	written, err := temporary.Write(data)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if written != len(data) {
		_ = temporary.Close()
		return fmt.Errorf("write temporary config: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := backupConfig(path); err != nil {
		return fmt.Errorf("backup config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("replace config: %w", err)
		}
		// Windows' MoveFile, used by os.Rename, does not replace an existing file.
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("replace config: %w (remove existing config: %v)", err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			return fmt.Errorf("replace config after removing existing config: %w", retryErr)
		}
	}
	committed = true
	return nil
}
