/** Human names for configuration keys shown in the change history. */
const LABELS: Record<string, string> = {
  'dns.listens': '监听地址',
  'dns.listen': '监听地址',
  'dns.upstreams': '上游服务器',
  'dns.fallback_upstreams': '备用上游',
  'dns.bootstrap_dns': 'Bootstrap DNS',
  'dns.upstream_mode': '上游分发策略',
  'dns.upstream_routes': '域名分流',
  'dns.local_records': '本地记录',
  'dns.private_reverse': '私网反向解析',
  'dns.block_aaaa': '禁用 AAAA',
  'dns.blocking_mode': '拦截模式',
  'dns.dnssec_validate': 'DNSSEC 验证',
  'web.listen': '控制台监听地址',
  'cache.enabled': '缓存开关',
  'cache.size': '缓存大小',
  'cache.optimistic': '乐观缓存',
  'rules.local_file': '规则文件',
  'rules.sources': '规则源',
  'logging.enabled': '日志持久化',
  'logging.file': '日志文件前缀',
  'logging.retention_days': '日志保留天数',
  'access.allowed_clients': '允许的客户端',
  'access.denied_clients': '拒绝的客户端',
  'access.client_rate_limit_qps': '客户端限速',
  'access.rebinding_protection': 'Rebinding 防护',
  'access.rebinding_allow_domains': 'Rebinding 例外域名',
  'encryption.enabled': '加密 DNS 开关',
  'encryption.certificate': '证书文件',
  'encryption.private_key': '私钥文件',
  'encryption.certificate_pem': '证书（PEM）',
  'encryption.private_key_pem': '私钥（PEM）',
  'encryption.dot_listens': 'DoT 监听地址',
  'encryption.doh_listens': 'DoH 监听地址',
  'encryption.doh3_listens': 'DoH3 监听地址',
  'encryption.doq_listens': 'DoQ 监听地址',
  'encryption.dnscrypt.enabled': 'DNSCrypt 开关',
  'encryption.dnscrypt.listens': 'DNSCrypt 监听地址',
  'encryption.dnscrypt.provider_name': 'DNSCrypt Provider 名称',
  'encryption.dnscrypt.private_key': 'DNSCrypt 密钥',
  'encryption.dnscrypt.resolver_secret': 'DNSCrypt 解析器密钥',
  'encryption.dnscrypt.certificate_ttl_hours': 'DNSCrypt 证书有效期'
};

export function settingLabel(key: string): string {
  if (LABELS[key]) return LABELS[key];
  if (key.startsWith('encryption.dnscrypt.')) return `DNSCrypt · ${key.slice('encryption.dnscrypt.'.length)}`;
  if (key.startsWith('encryption.')) return `加密 DNS · ${key.slice('encryption.'.length)}`;
  return key;
}
