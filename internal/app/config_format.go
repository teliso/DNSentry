package app

import (
	"github.com/teliso/DNSentry/internal/rules"
	"path/filepath"
	"strings"
)

type yamlConfig struct {
	Version int `yaml:"version"`
	DNS     struct {
		Listen                string        `yaml:"listen"`
		Listens               []string      `yaml:"listens,omitempty"`
		Upstreams             []string      `yaml:"upstreams"`
		FallbackUpstreams     []string      `yaml:"fallback_upstreams"`
		UpstreamMode          string        `yaml:"upstream_mode"`
		LocalRecords          []LocalRecord `yaml:"local_records,omitempty"`
		BootstrapDNS          []string      `yaml:"bootstrap_dns"`
		UpstreamTimeout       int           `yaml:"upstream_timeout_seconds"`
		BlockingMode          string        `yaml:"blocking_mode"`
		BlockingIPv4          string        `yaml:"blocking_ipv4"`
		BlockingIPv6          string        `yaml:"blocking_ipv6"`
		EnableDNSSEC          bool          `yaml:"enable_dnssec"`
		DNSSECValidate        bool          `yaml:"dnssec_validate"`
		DNSSECTrustAnchors    []string      `yaml:"dnssec_trust_anchors"`
		DNSSECTrustAnchorFile string        `yaml:"dnssec_trust_anchor_file"`
		DNSSECAutoUpdate      bool          `yaml:"dnssec_auto_update"`
		BlockedResponseTTL    uint32        `yaml:"blocked_response_ttl"`
	} `yaml:"dns"`
	Web struct {
		Listen string `yaml:"listen"`
	} `yaml:"web"`
	Cache struct {
		Enabled             *bool  `yaml:"enabled"`
		Size                int    `yaml:"size"`
		TTLMin              uint32 `yaml:"ttl_min"`
		TTLMax              uint32 `yaml:"ttl_max"`
		Optimistic          bool   `yaml:"optimistic"`
		OptimisticAnswerTTL uint32 `yaml:"optimistic_answer_ttl"`
		OptimisticMaxAge    uint32 `yaml:"optimistic_max_age"`
	} `yaml:"cache"`
	Rules struct {
		LocalFile string         `yaml:"local_file"`
		Sources   []rules.Source `yaml:"sources,omitempty"`
	} `yaml:"rules"`
	Access     DNSAccessConfig  `yaml:"access"`
	Encryption EncryptionConfig `yaml:"encryption"`
	Logging    struct {
		QueryLogSize          int    `yaml:"query_log_size"`
		QueryLogEnabled       bool   `yaml:"enabled"`
		QueryLogFile          string `yaml:"file"`
		QueryLogRetentionDays int    `yaml:"retention_days"`
	} `yaml:"logging"`
}

func (f yamlConfig) toConfig() *Config {
	enabled := true
	if f.Cache.Enabled != nil {
		enabled = *f.Cache.Enabled
	}
	queryLogFile := strings.TrimSpace(f.Logging.QueryLogFile)
	if queryLogFile == "" {
		queryLogFile = filepath.Join("data", "querylog")
	}
	queryLogRetentionDays := f.Logging.QueryLogRetentionDays
	if queryLogRetentionDays == 0 {
		queryLogRetentionDays = 7
	}
	return &Config{
		DNSListen:             f.DNS.Listen,
		DNSListens:            append([]string(nil), f.DNS.Listens...),
		HTTPListen:            f.Web.Listen,
		Upstreams:             f.DNS.Upstreams,
		FallbackUpstreams:     f.DNS.FallbackUpstreams,
		UpstreamMode:          f.DNS.UpstreamMode,
		LocalRecords:          append([]LocalRecord(nil), f.DNS.LocalRecords...),
		BootstrapDNS:          f.DNS.BootstrapDNS,
		UpstreamTimeout:       f.DNS.UpstreamTimeout,
		BlockingMode:          f.DNS.BlockingMode,
		BlockingIPv4:          f.DNS.BlockingIPv4,
		BlockingIPv6:          f.DNS.BlockingIPv6,
		EnableDNSSEC:          f.DNS.EnableDNSSEC,
		DNSSECValidate:        f.DNS.DNSSECValidate,
		DNSSECTrustAnchors:    append([]string(nil), f.DNS.DNSSECTrustAnchors...),
		DNSSECTrustAnchorFile: f.DNS.DNSSECTrustAnchorFile,
		DNSSECAutoUpdate:      f.DNS.DNSSECAutoUpdate,
		BlockedResponseTTL:    f.DNS.BlockedResponseTTL,
		RulesFile:             f.Rules.LocalFile,
		CacheEnabled:          enabled,
		CacheSize:             f.Cache.Size,
		QueryLogSize:          f.Logging.QueryLogSize,
		QueryLogEnabled:       f.Logging.QueryLogEnabled,
		QueryLogFile:          queryLogFile,
		QueryLogRetentionDays: queryLogRetentionDays,
		CacheTTLMin:           f.Cache.TTLMin,
		CacheTTLMax:           f.Cache.TTLMax,
		OptimisticCache:       f.Cache.Optimistic,
		OptimisticAnswerTTL:   f.Cache.OptimisticAnswerTTL,
		OptimisticMaxAge:      f.Cache.OptimisticMaxAge,
		RuleSources:           f.Rules.Sources,
		Access:                f.Access,
		Encryption:            f.Encryption,
	}
}

func newYAMLConfig(config *Config) yamlConfig {
	fileConfig := yamlConfig{Version: 1}
	fileConfig.DNS.Listen = config.DNSListen
	fileConfig.DNS.Listens = append([]string(nil), config.DNSListens...)
	fileConfig.DNS.Upstreams = config.Upstreams
	fileConfig.DNS.FallbackUpstreams = config.FallbackUpstreams
	fileConfig.DNS.UpstreamMode = config.UpstreamMode
	fileConfig.DNS.LocalRecords = append([]LocalRecord(nil), config.LocalRecords...)
	fileConfig.DNS.BootstrapDNS = config.BootstrapDNS
	fileConfig.DNS.UpstreamTimeout = config.UpstreamTimeout
	fileConfig.DNS.BlockingMode = config.BlockingMode
	fileConfig.DNS.BlockingIPv4 = config.BlockingIPv4
	fileConfig.DNS.BlockingIPv6 = config.BlockingIPv6
	fileConfig.DNS.EnableDNSSEC = config.EnableDNSSEC
	fileConfig.DNS.DNSSECValidate = config.DNSSECValidate
	fileConfig.DNS.DNSSECTrustAnchors = append([]string(nil), config.DNSSECTrustAnchors...)
	fileConfig.DNS.DNSSECTrustAnchorFile = config.DNSSECTrustAnchorFile
	fileConfig.DNS.DNSSECAutoUpdate = config.DNSSECAutoUpdate
	fileConfig.DNS.BlockedResponseTTL = config.BlockedResponseTTL
	fileConfig.Web.Listen = config.HTTPListen
	fileConfig.Cache.Enabled = boolPtr(config.CacheEnabled)
	fileConfig.Cache.Size = config.CacheSize
	fileConfig.Cache.TTLMin = config.CacheTTLMin
	fileConfig.Cache.TTLMax = config.CacheTTLMax
	fileConfig.Cache.Optimistic = config.OptimisticCache
	fileConfig.Cache.OptimisticAnswerTTL = config.OptimisticAnswerTTL
	fileConfig.Cache.OptimisticMaxAge = config.OptimisticMaxAge
	fileConfig.Rules.LocalFile = config.RulesFile
	fileConfig.Rules.Sources = config.RuleSources
	fileConfig.Access = config.Access
	fileConfig.Logging.QueryLogSize = config.QueryLogSize
	fileConfig.Logging.QueryLogEnabled = config.QueryLogEnabled
	fileConfig.Logging.QueryLogFile = config.QueryLogFile
	fileConfig.Logging.QueryLogRetentionDays = config.QueryLogRetentionDays
	fileConfig.Encryption = config.Encryption
	return fileConfig
}

func boolPtr(value bool) *bool { return &value }
