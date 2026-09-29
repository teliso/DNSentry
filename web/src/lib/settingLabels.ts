/** Human names for configuration keys shown in the change history. */
const LABELS: Record<string, string> = {
  'dns.listens': '监听地址',
  'dns.listen': '监听地址',
  'dns.upstreams': '上游服务器',
  'dns.fallback_upstreams': '备用上游',
  'dns.bootstrap_dns': 'Bootstrap DNS',
  'dns.upstream_mode': '上游分发策略',
  'dns.upstream_timeout_seconds': '上游超时',
  'dns.upstream_routes': '域名分流',
  'dns.local_records': '本地记录',
  'dns.private_reverse': '私网反向解析',
  'dns.block_aaaa': '禁用 AAAA',
  'dns.blocking_mode': '拦截模式',
  'dns.blocking_ipv4': '拦截响应 IPv4',
  'dns.blocking_ipv6': '拦截响应 IPv6',
  'dns.blocked_response_ttl': '拦截响应 TTL',
  'dns.enable_dnssec': '请求 DNSSEC',
  'dns.dnssec_validate': 'DNSSEC 验证',
  'dns.dnssec_trust_anchors': 'DNSSEC 信任锚',
  'dns.dnssec_trust_anchor_file': 'DNSSEC 信任锚文件',
  'dns.dnssec_auto_update': 'DNSSEC 自动更新',
  'web.listen': '控制台监听地址',
  'cache.enabled': '缓存开关',
  'cache.size': '缓存大小',
  'cache.ttl_min': '缓存 TTL 下限',
  'cache.ttl_max': '缓存 TTL 上限',
  'cache.prefetch': '缓存预取',
  'cache.optimistic': '乐观缓存',
  'cache.optimistic_answer_ttl': '乐观缓存 TTL',
  'cache.optimistic_max_age': '乐观缓存最大寿命',
  'rules.local_file': '规则文件',
  'rules.sources': '规则源',
  'logging.query_log_size': '内存日志条数',
  'logging.enabled': '日志持久化',
  'logging.file': '日志文件前缀',
  'logging.retention_days': '日志保留天数',
  'access.allowed_clients': '允许的客户端',
  'access.denied_clients': '拒绝的客户端',
  'access.client_rate_limit_qps': '客户端限速',
  'access.max_concurrent_queries': '最大并发查询',
  'access.rebinding_protection': 'Rebinding 防护',
  'access.rebinding_allow_domains': 'Rebinding 例外域名'
};

export function settingLabel(key: string): string {
  if (LABELS[key]) return LABELS[key];
  if (key.startsWith('encryption.dnscrypt.')) return `DNSCrypt · ${key.slice('encryption.dnscrypt.'.length)}`;
  if (key.startsWith('encryption.')) return `加密 DNS · ${key.slice('encryption.'.length)}`;
  return key;
}
