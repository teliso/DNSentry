import { hostOf } from './rules';
import type { Route } from './router.svelte';
import type { Status } from './types';

export type Alert = { id: string; tone: 'warn' | 'danger'; text: string; route?: Route; action?: string };

const DAY_MS = 24 * 60 * 60 * 1000;

/** Problems worth showing on every page, derived from the live status. */
export function computeAlerts(status: Status | null, now = Date.now()): Alert[] {
  if (!status) return [];
  const alerts: Alert[] = [];

  if (status.restart_required) {
    alerts.push({ id: 'restart', tone: 'warn', text: '已保存的配置中有监听地址、查询日志或加密 DNS 的改动，需要重启服务后生效；其余设置已即时应用。' });
  }

  const health = status.upstream_health ?? [];
  if (health.length > 0 && health.every((upstream) => !upstream.healthy)) {
    alerts.push({
      id: 'upstreams-down',
      tone: 'danger',
      text: '所有默认上游都处于失败状态，未命中缓存和规则的查询会失败（备用上游会在这种情况下接管）。',
      route: 'dns',
      action: '检查上游'
    });
  }
  for (const route of status.upstream_routes ?? []) {
    if (route.upstreams.length > 0 && route.upstreams.every((upstream) => !upstream.healthy)) {
      alerts.push({
        id: `route-down-${route.domains.join(',')}`,
        tone: 'danger',
        text: `域名分流“${route.name || route.domains[0]}”的专属上游全部失败，这些域名会解析失败（不会回退到默认上游）。`,
        route: 'dns',
        action: '检查分流'
      });
    }
  }

  for (const source of status.rule_sources ?? []) {
    if (!source.enabled || !source.last_error) continue;
    const checked = source.last_checked ? new Date(source.last_checked).getTime() : NaN;
    const interval = source.interval_minutes * 60_000;
    const stale = Number.isNaN(checked) || now - checked > Math.max(DAY_MS, 2 * interval);
    if (!stale) continue;
    const name = source.name || hostOf(source.url);
    const since = Number.isNaN(checked) ? '从未成功下载' : `超过 ${Math.floor((now - checked) / DAY_MS)} 天没有成功更新`;
    alerts.push({
      id: `source-${source.url}`,
      tone: 'warn',
      text: `规则源“${name}”${since}：${source.last_error}${source.rule_count ? '（仍在使用缓存的规则）' : ''}`,
      route: 'sources',
      action: '查看规则源'
    });
  }
  return alerts;
}
