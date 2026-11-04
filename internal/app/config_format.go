package app

import (
	"strings"

	"github.com/teliso/DNSentry/internal/rules"
)

type yamlConfig struct {
	Version int `yaml:"version"`
	DNS     struct {
		Listen            string          `yaml:"listen,omitempty"` // legacy single address: read from old files, never written
		Listens           []string        `yaml:"listens,omitempty"`
		Upstreams         []string        `yaml:"upstreams"`
		FallbackUpstreams []string        `yaml:"fallback_upstreams"`
		UpstreamMode      string          `yaml:"upstream_mode"`
		LocalRecords      []LocalRecord   `yaml:"local_records,omitempty"`
		UpstreamRoutes    []UpstreamRoute `yaml:"upstream_routes,omitempty"`
		PrivateReverse    *bool           `yaml:"private_reverse"`
		BlockAAAA         bool            `yaml:"block_aaaa"`
		BootstrapDNS      []string        `yaml:"bootstrap_dns"`
		BlockingMode      string          `yaml:"blocking_mode"`
		DNSSECValidate    bool            `yaml:"dnssec_validate"`
	} `yaml:"dns"`
	Web struct {
		Listen string `yaml:"listen"`
	} `yaml:"web"`
	Cache struct {
		Enabled    *bool `yaml:"enabled"`
		Size       int   `yaml:"size"`
		Optimistic bool  `yaml:"optimistic"`
	} `yaml:"cache"`
	Rules struct {
		LocalFile string         `yaml:"local_file,omitempty"`
		Sources   []rules.Source `yaml:"sources,omitempty"`
	} `yaml:"rules"`
	Access     DNSAccessConfig  `yaml:"access"`
	Encryption EncryptionConfig `yaml:"encryption"`
	Logging    struct {
		QueryLogEnabled       bool   `yaml:"enabled"`
		QueryLogFile          string `yaml:"file,omitempty"`
		QueryLogRetentionDays int    `yaml:"retention_days"`
	} `yaml:"logging"`
}

func (f yamlConfig) toConfig() *Config {
	// "listen" is the pre-list form of "listens"; still read, never written.
	dnsListens := append([]string(nil), f.DNS.Listens...)
	if len(dnsListens) == 0 && strings.TrimSpace(f.DNS.Listen) != "" {
		dnsListens = []string{f.DNS.Listen}
	}
	privateReverse := true
	if f.DNS.PrivateReverse != nil {
		privateReverse = *f.DNS.PrivateReverse
	}
	enabled := true
	if f.Cache.Enabled != nil {
		enabled = *f.Cache.Enabled
	}
	rulesFile := strings.TrimSpace(f.Rules.LocalFile)
	if rulesFile == "" {
		rulesFile = defaultRulesFile()
	}
	queryLogFile := strings.TrimSpace(f.Logging.QueryLogFile)
	if queryLogFile == "" {
		queryLogFile = defaultQueryLogFile()
	}
	queryLogRetentionDays := f.Logging.QueryLogRetentionDays
	if queryLogRetentionDays == 0 {
		queryLogRetentionDays = 7
	}
	return &Config{
		DNSListens:            dnsListens,
		HTTPListen:            f.Web.Listen,
		Upstreams:             f.DNS.Upstreams,
		FallbackUpstreams:     f.DNS.FallbackUpstreams,
		UpstreamMode:          f.DNS.UpstreamMode,
		LocalRecords:          append([]LocalRecord(nil), f.DNS.LocalRecords...),
		UpstreamRoutes:        append([]UpstreamRoute(nil), f.DNS.UpstreamRoutes...),
		PrivateReverse:        privateReverse,
		BlockAAAA:             f.DNS.BlockAAAA,
		BootstrapDNS:          f.DNS.BootstrapDNS,
		BlockingMode:          f.DNS.BlockingMode,
		DNSSECValidate:        f.DNS.DNSSECValidate,
		RulesFile:             rulesFile,
		CacheEnabled:          enabled,
		CacheSize:             f.Cache.Size,
		QueryLogEnabled:       f.Logging.QueryLogEnabled,
		QueryLogFile:          queryLogFile,
		QueryLogRetentionDays: queryLogRetentionDays,
		OptimisticCache:       f.Cache.Optimistic,
		RuleSources:           f.Rules.Sources,
		Access:                f.Access,
		Encryption:            f.Encryption,
	}
}

func newYAMLConfig(config *Config) yamlConfig {
	fileConfig := yamlConfig{Version: 1}
	fileConfig.DNS.Listens = append([]string(nil), config.DNSListens...)
	fileConfig.DNS.Upstreams = config.Upstreams
	fileConfig.DNS.FallbackUpstreams = config.FallbackUpstreams
	fileConfig.DNS.UpstreamMode = config.UpstreamMode
	fileConfig.DNS.LocalRecords = append([]LocalRecord(nil), config.LocalRecords...)
	fileConfig.DNS.UpstreamRoutes = append([]UpstreamRoute(nil), config.UpstreamRoutes...)
	fileConfig.DNS.PrivateReverse = boolPtr(config.PrivateReverse)
	fileConfig.DNS.BlockAAAA = config.BlockAAAA
	fileConfig.DNS.BootstrapDNS = config.BootstrapDNS
	fileConfig.DNS.BlockingMode = config.BlockingMode
	fileConfig.DNS.DNSSECValidate = config.DNSSECValidate
	fileConfig.Web.Listen = config.HTTPListen
	fileConfig.Cache.Enabled = boolPtr(config.CacheEnabled)
	fileConfig.Cache.Size = config.CacheSize
	fileConfig.Cache.Optimistic = config.OptimisticCache
	// Paths that follow the data directory are left out, so a config file
	// stays valid when its directory is moved.
	if config.RulesFile != defaultRulesFile() {
		fileConfig.Rules.LocalFile = config.RulesFile
	}
	fileConfig.Rules.Sources = config.RuleSources
	fileConfig.Access = config.Access
	fileConfig.Logging.QueryLogEnabled = config.QueryLogEnabled
	if config.QueryLogFile != defaultQueryLogFile() {
		fileConfig.Logging.QueryLogFile = config.QueryLogFile
	}
	fileConfig.Logging.QueryLogRetentionDays = config.QueryLogRetentionDays
	fileConfig.Encryption = config.Encryption
	return fileConfig
}

func boolPtr(value bool) *bool { return &value }
