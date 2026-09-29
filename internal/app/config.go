package app

import "github.com/teliso/DNSentry/internal/rules"

// Config is the effective service configuration. JSON tags describe the Web API
// shape; the on-disk YAML layout lives in config_format.go.
type Config struct {
	DNSListen             string           `json:"dns_listen"`
	DNSListens            []string         `json:"dns_listens,omitempty"`
	HTTPListen            string           `json:"http_listen"`
	Upstreams             []string         `json:"upstreams"`
	FallbackUpstreams     []string         `json:"fallback_upstreams"`
	UpstreamMode          string           `json:"upstream_mode"`
	LocalRecords          []LocalRecord    `json:"local_records,omitempty"`
	BootstrapDNS          []string         `json:"bootstrap_dns"`
	UpstreamTimeout       int              `json:"upstream_timeout_seconds"`
	BlockingMode          string           `json:"blocking_mode"`
	BlockingIPv4          string           `json:"blocking_ipv4"`
	BlockingIPv6          string           `json:"blocking_ipv6"`
	EnableDNSSEC          bool             `json:"enable_dnssec"`
	DNSSECValidate        bool             `json:"dnssec_validate"`
	DNSSECTrustAnchors    []string         `json:"dnssec_trust_anchors,omitempty"`
	DNSSECTrustAnchorFile string           `json:"dnssec_trust_anchor_file"`
	DNSSECAutoUpdate      bool             `json:"dnssec_auto_update"`
	BlockedResponseTTL    uint32           `json:"blocked_response_ttl"`
	RulesFile             string           `json:"rules_file"`
	CacheEnabled          bool             `json:"cache_enabled"`
	CacheSize             int              `json:"cache_size"`
	QueryLogSize          int              `json:"query_log_size"`
	QueryLogEnabled       bool             `json:"query_log_enabled"`
	QueryLogFile          string           `json:"query_log_file"`
	QueryLogRetentionDays int              `json:"query_log_retention_days"`
	CacheTTLMin           uint32           `json:"cache_ttl_min"`
	CacheTTLMax           uint32           `json:"cache_ttl_max"`
	OptimisticCache       bool             `json:"cache_optimistic"`
	OptimisticAnswerTTL   uint32           `json:"cache_optimistic_answer_ttl"`
	OptimisticMaxAge      uint32           `json:"cache_optimistic_max_age"`
	RuleSources           []rules.Source   `json:"rule_sources,omitempty"`
	Access                DNSAccessConfig  `json:"access" yaml:"access"`
	Encryption            EncryptionConfig `json:"encryption" yaml:"encryption"`
}
