const numberFormat = new Intl.NumberFormat('zh-CN');

export const formatNumber = (value: number) => numberFormat.format(value);

/** 12345 -> "1.2 万" style compaction keeps tiles readable. */
export function formatCompact(value: number): string {
  if (value >= 100_000_000) return `${(value / 100_000_000).toFixed(1)} 亿`;
  if (value >= 10_000) return `${(value / 10_000).toFixed(1)} 万`;
  return formatNumber(value);
}

export function formatDuration(ms: number): string {
  if (!ms) return '0 ms';
  return `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export const formatPercent = (ratio: number) => `${(ratio * 100).toFixed(ratio > 0 && ratio < 0.1 ? 1 : 0)}%`;

export function formatClock(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatRelative(value: string | undefined, now = Date.now()): string {
  if (!value) return '—';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return value;
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 60) return '刚刚';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

export type Tone = 'neutral' | 'ok' | 'danger' | 'warn' | 'accent';

/** Display name and tone for the `action` recorded on each query log entry. */
export const ACTION_LABELS: Record<string, { label: string; tone: Tone }> = {
  block: { label: '已拦截', tone: 'danger' },
  rewrite: { label: '已改写', tone: 'accent' },
  local: { label: '本地记录', tone: 'accent' },
  cached: { label: '缓存命中', tone: 'ok' },
  optimistic: { label: '乐观缓存', tone: 'ok' },
  forwarded: { label: '已转发', tone: 'neutral' },
  allow: { label: '已放行', tone: 'neutral' },
  denied: { label: '客户端拒绝', tone: 'warn' },
  rate_limited: { label: '已限速', tone: 'warn' },
  overloaded: { label: '过载', tone: 'warn' },
  rebinding_blocked: { label: 'Rebinding 拦截', tone: 'danger' },
  error: { label: '解析失败', tone: 'danger' }
};

export const actionInfo = (action: string) => ACTION_LABELS[action] ?? { label: action, tone: 'neutral' as Tone };
