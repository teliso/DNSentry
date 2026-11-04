import { serializeConfig } from './config';
import { formatBytes } from './format';
import type { Config } from './types';

export type Change = {
  path: string;
  label: string;
  /** Primitive settings: the old and new value. */
  before?: string;
  after?: string;
  /** List settings: what was added and removed. */
  added?: string[];
  removed?: string[];
};

/** Settings that hold secrets: a change is reported, the value is not shown. */
const SECRET = new Set(['encryption.private_key_pem', 'encryption.dnscrypt.private_key', 'encryption.dnscrypt.resolver_secret']);

const LABELS: Record<string, string> = {
  dns_listens: 'DNS 监听地址',
  http_listen: '控制台监听地址',
  upstreams: '上游服务器',
  fallback_upstreams: '备用上游',
  bootstrap_dns: 'Bootstrap DNS',
  upstream_mode: '请求分发策略',
  upstream_timeout_seconds: '上游超时（秒）',
  upstream_routes: '域名分流',
  local_records: '本地记录',
  private_reverse: '私网反向解析',
  block_aaaa: '不解析 IPv6（AAAA）',
  blocked_services: '屏蔽的服务',
  safe_search: '强制安全搜索',
  blocking_mode: '拦截响应方式',
  blocking_ipv4: '拦截响应 IPv4',
  blocking_ipv6: '拦截响应 IPv6',
  blocked_response_ttl: '拦截响应 TTL',
  enable_dnssec: '向上游请求 DNSSEC',
  dnssec_validate: 'DNSSEC 验证',
  dnssec_trust_anchors: 'DNSSEC 信任锚',
  dnssec_trust_anchor_file: 'DNSSEC 信任锚文件',
  dnssec_auto_update: 'DNSSEC 自动更新',
  rules_file: '本地规则文件',
  cache_enabled: '启用缓存',
  cache_size: '缓存大小',
  cache_ttl_min: '缓存 TTL 下限',
  cache_ttl_max: '缓存 TTL 上限',
  cache_prefetch: '预取热门条目',
  cache_optimistic: '乐观缓存',
  cache_optimistic_answer_ttl: '乐观应答 TTL',
  cache_optimistic_max_age: '乐观缓存最大寿命',
  query_log_size: '内存日志条数',
  query_log_enabled: '保存日志到磁盘',
  query_log_file: '日志文件前缀',
  query_log_retention_days: '日志保留天数',
  'access.allowed_clients': '允许的客户端',
  'access.denied_clients': '拒绝的客户端',
  'access.client_rate_limit_qps': '单客户端速率限制',
  'access.max_concurrent_queries': '最大并发查询',
  'access.rebinding_protection': 'DNS Rebinding 防护',
  'access.rebinding_allow_domains': 'Rebinding 例外域名',
  'web_tls.enabled': '控制台 HTTPS',
  'web_tls.source': '控制台证书来源',
  'web_tls.certificate': '控制台证书文件',
  'web_tls.private_key': '控制台私钥文件',
  'web_tls.server_name': '控制台绑定域名',
  'schedule.timezone': '计划时区',
  'schedule.rules': '计划任务',
  'notifications.webhooks': '通知 Webhook',
  'notifications.events': '通知的事件',
  'encryption.enabled': '加密 DNS 服务',
  'encryption.certificate': '加密 DNS 证书文件',
  'encryption.private_key': '加密 DNS 私钥文件',
  'encryption.certificate_pem': '加密 DNS 证书（PEM）',
  'encryption.private_key_pem': '加密 DNS 私钥（PEM）',
  'encryption.dot_listens': 'DoT 监听地址',
  'encryption.doh_listens': 'DoH 监听地址',
  'encryption.doh3_listens': 'DoH3 监听地址',
  'encryption.doq_listens': 'DoQ 监听地址',
  'encryption.dnscrypt.enabled': 'DNSCrypt',
  'encryption.dnscrypt.listens': 'DNSCrypt 监听地址',
  'encryption.dnscrypt.provider_name': 'DNSCrypt Provider 名称',
  'encryption.dnscrypt.private_key': 'DNSCrypt 密钥',
  'encryption.dnscrypt.resolver_secret': 'DNSCrypt 解析器密钥',
  'encryption.dnscrypt.certificate_ttl_hours': 'DNSCrypt 证书有效期（小时）'
};

const BYTES = new Set(['cache_size']);
const EMPTY = '（空）';

function flatten(value: unknown, prefix: string, out: Map<string, unknown>) {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) flatten(child, prefix ? `${prefix}.${key}` : key, out);
  } else {
    out.set(prefix, value);
  }
}

/** One line describing a list item (a record, a route, a webhook …). */
function describe(item: unknown): string {
  if (item === null || typeof item !== 'object') return String(item);
  const entry = item as Record<string, unknown>;
  if ('domain' in entry && 'type' in entry) return `${entry.domain} ${entry.type} ${entry.value}`;
  if ('domains' in entry && 'upstreams' in entry) return `${entry.name ? `${entry.name}：` : ''}${(entry.domains as string[]).join(', ')} → ${(entry.upstreams as string[]).join(', ')}`;
  if ('url' in entry) return `${entry.name ? `${entry.name}：` : ''}${entry.url}${entry.enabled === false ? '（停用）' : ''}`;
  if ('start' in entry && 'end' in entry) return `${entry.name || '计划'}：${entry.start}–${entry.end}，${(entry.services as string[]).length} 个服务${entry.enabled === false ? '（停用）' : ''}`;
  return JSON.stringify(item);
}

function scalar(path: string, value: unknown): string {
  if (typeof value === 'boolean') return value ? '开' : '关';
  if (value === '' || value === null || value === undefined) return EMPTY;
  if (BYTES.has(path) && typeof value === 'number') return formatBytes(value);
  return String(value);
}

/** What differs between the saved configuration and the editable draft, in terms the user would recognise. */
export function diffConfig(saved: Config, draft: Config): Change[] {
  const before = new Map<string, unknown>();
  const after = new Map<string, unknown>();
  flatten(serializeConfig(saved), '', before);
  flatten(serializeConfig(draft), '', after);
  const changes: Change[] = [];
  for (const path of new Set([...before.keys(), ...after.keys()])) {
    const old = before.get(path);
    const next = after.get(path);
    if (JSON.stringify(old) === JSON.stringify(next)) continue;
    const label = LABELS[path] ?? path;
    if (SECRET.has(path)) {
      changes.push({ path, label, before: '••••', after: '••••' });
    } else if (Array.isArray(old) || Array.isArray(next)) {
      const oldItems = ((old as unknown[]) ?? []).map(describe);
      const newItems = ((next as unknown[]) ?? []).map(describe);
      // Compare as multisets so that moving an item is not reported as a change.
      const removed = [...oldItems];
      const added: string[] = [];
      for (const item of newItems) {
        const index = removed.indexOf(item);
        if (index >= 0) removed.splice(index, 1);
        else added.push(item);
      }
      if (added.length > 0 || removed.length > 0) changes.push({ path, label, added, removed });
      else changes.push({ path, label, before: oldItems.join(', ') || EMPTY, after: newItems.join(', ') || EMPTY }); // same items, different order
    } else {
      changes.push({ path, label, before: scalar(path, old), after: scalar(path, next) });
    }
  }
  return changes.sort((a, b) => a.label.localeCompare(b.label, 'zh-CN'));
}
