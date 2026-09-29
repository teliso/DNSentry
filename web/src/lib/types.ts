// Shapes of the DNSentry JSON API (see internal/app/api*.go).

export type RuleAction = 'block' | 'allow';
/** A filter rule; `source` is empty for the local rules file, else the list URL. */
export type Rule = { domain: string; action: RuleAction; ip?: string; source?: string };
export type RulePage = { total: number; items: Rule[] };
export type RuleQuery = { search?: string; action?: RuleAction | ''; source?: string; offset?: number; limit?: number };
export type RuleCheck = { domain: string; rule?: Rule; candidates: Rule[] };
export type LocalSummary = { rules: number; ignored: number; ignored_lines: number[] };

export type MetricPoint = { time: string; queries: number; blocked: number };
export type RankedCount = { name: string; count: number };
export type Dashboard = {
  average_processing_ms: number;
  client_ips: RankedCount[];
  domains: RankedCount[];
  blocked_domains: RankedCount[];
  upstreams: { address: string; count: number; average_duration_ms: number }[];
  slow_domains: { name: string; count: number; average_duration_ms: number }[];
  failed_domains: RankedCount[];
};

export type UpstreamHealth = {
  address: string;
  healthy: boolean;
  failures: number;
  requests: number;
  successes: number;
  latency_ms: number;
  last_success?: string;
  last_failure?: string;
};
export type UpstreamTest = { address: string; protocol: string; success: boolean; latency_ms: number; error?: string };

export type RuleSource = {
  url: string;
  name?: string;
  enabled: boolean;
  interval_minutes: number;
  // Runtime status (read-only)
  last_updated?: string;
  last_checked?: string;
  last_error?: string;
  rule_count?: number;
  updating?: boolean;
};

export type CacheStats = {
  entries: number;
  used_bytes: number;
  max_bytes: number;
  hits: number;
  misses: number;
  stale_hits: number;
  evictions: number;
  bypasses: number;
  refresh_success: number;
  refresh_failure: number;
  prefetches: number;
  hit_rate: number;
};
export type DNSSECStats = { secure: number; insecure: number; bogus: number; indeterminate: number };
export type SecurityStats = { denied_clients: number; rate_limited: number; overloaded: number; rebinding_blocked: number };
export type DNSCryptStatus = {
  enabled: boolean;
  running: boolean;
  listen: string;
  listens?: string[];
  provider_name: string;
  stamp?: string;
  udp: boolean;
  tcp: boolean;
};

export type Status = {
  /** Saved configuration has startup-only changes that need a service restart. */
  restart_required: boolean;
  version: string;
  config_path: string;
  rules_file: string;
  dns_listen: string;
  dns_listens: string[];
  http_listen: string;
  upstreams: string[];
  fallback_upstreams: string[];
  upstream_health: UpstreamHealth[];
  upstream_routes: RouteStatus[];
  fallback_upstream_health: UpstreamHealth[];
  rule_sources: RuleSource[];
  total_queries: number;
  blocked_queries: number;
  rules: number;
  local_rules: number;
  cache: CacheStats;
  dnssec: DNSSECStats;
  security: SecurityStats;
  dnscrypt: DNSCryptStatus;
  series: MetricPoint[];
  dashboard: Dashboard;
};

export type LogEntry = {
  time: string;
  client?: string;
  domain: string;
  type: string;
  action: string;
  upstream?: string;
  duration_ms: number;
  rule?: string;
  rule_source?: string;
};

export type LogQuery = { search?: string; action?: string; offset?: number; limit?: number };
export type LogPage = { total: number; items: LogEntry[]; actions: string[] };

export type LocalRecordType = 'A' | 'AAAA' | 'CNAME' | 'TXT';
export type LocalRecord = { domain: string; type: LocalRecordType; value: string; ttl: number };

export type DNSCryptConfig = {
  enabled: boolean;
  listen: string;
  listens: string[];
  provider_name: string;
  private_key: string;
  resolver_secret: string;
  certificate_ttl_hours: number;
};

export type SecureProtocol = 'dot' | 'doh' | 'doh3' | 'doq';

export type EncryptionConfig = {
  enabled: boolean;
  certificate: string;
  private_key: string;
  certificate_pem: string;
  private_key_pem: string;
  dot_listen: string;
  dot_listens: string[];
  doh_listen: string;
  doh_listens: string[];
  doh3_listen: string;
  doh3_listens: string[];
  doq_listen: string;
  doq_listens: string[];
  dnscrypt: DNSCryptConfig;
};

export type AccessConfig = {
  allowed_clients: string[];
  denied_clients: string[];
  client_rate_limit_qps: number;
  max_concurrent_queries: number;
  rebinding_protection: boolean;
  rebinding_allow_domains: string[];
};

export type UpstreamRoute = { name?: string; domains: string[]; upstreams: string[] };
export type RouteStatus = { name?: string; domains: string[]; upstreams: UpstreamHealth[] };

export type UpstreamMode = 'load_balance' | 'parallel' | 'fastest_addr';
export type BlockingMode = 'default' | 'nxdomain' | 'null_ip' | 'custom_ip' | 'refused';

export type Config = {
  dns_listen: string;
  dns_listens: string[];
  http_listen: string;
  upstreams: string[];
  fallback_upstreams: string[];
  upstream_mode: UpstreamMode;
  local_records: LocalRecord[];
  upstream_routes: UpstreamRoute[];
  private_reverse: boolean;
  block_aaaa: boolean;
  access: AccessConfig;
  bootstrap_dns: string[];
  upstream_timeout_seconds: number;
  blocking_mode: BlockingMode;
  blocking_ipv4: string;
  blocking_ipv6: string;
  blocked_response_ttl: number;
  enable_dnssec: boolean;
  dnssec_validate: boolean;
  dnssec_trust_anchors: string[];
  dnssec_trust_anchor_file: string;
  dnssec_auto_update: boolean;
  rules_file: string;
  cache_enabled: boolean;
  cache_size: number;
  cache_ttl_min: number;
  cache_ttl_max: number;
  cache_prefetch: boolean;
  cache_optimistic: boolean;
  cache_optimistic_answer_ttl: number;
  cache_optimistic_max_age: number;
  query_log_size: number;
  query_log_enabled: boolean;
  query_log_file: string;
  query_log_retention_days: number;
  encryption: EncryptionConfig;
};
