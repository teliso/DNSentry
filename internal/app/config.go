package app

import "github.com/teliso/DNSentry/internal/rules"

// Config is the effective service configuration. JSON tags describe the Web API
// shape; the on-disk YAML layout lives in config_format.go.
type Config struct {
	DNSListens            []string         `json:"dns_listens,omitempty"`
	HTTPListen            string           `json:"http_listen"`
	Upstreams             []string         `json:"upstreams"`
	FallbackUpstreams     []string         `json:"fallback_upstreams"`
	UpstreamMode          string           `json:"upstream_mode"`
	LocalRecords          []LocalRecord    `json:"local_records,omitempty"`
	UpstreamRoutes        []UpstreamRoute  `json:"upstream_routes"`
	PrivateReverse        bool             `json:"private_reverse"`
	BlockAAAA             bool             `json:"block_aaaa"`
	BootstrapDNS          []string         `json:"bootstrap_dns"`
	BlockingMode          string           `json:"blocking_mode"`
	DNSSECValidate        bool             `json:"dnssec_validate"`
	RulesFile             string           `json:"rules_file"`
	CacheEnabled          bool             `json:"cache_enabled"`
	CacheSize             int              `json:"cache_size"`
	QueryLogEnabled       bool             `json:"query_log_enabled"`
	QueryLogFile          string           `json:"query_log_file"`
	QueryLogRetentionDays int              `json:"query_log_retention_days"`
	OptimisticCache       bool             `json:"cache_optimistic"`
	RuleSources           []rules.Source   `json:"rule_sources,omitempty"`
	Access                DNSAccessConfig  `json:"access" yaml:"access"`
	Encryption            EncryptionConfig `json:"encryption" yaml:"encryption"`
}
