<script lang="ts">
  import BarList from '../components/BarList.svelte';
  import Card from '../components/Card.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Stat from '../components/Stat.svelte';
  import TrafficChart from '../components/TrafficChart.svelte';
  import { formatBytes, formatCompact, formatDuration, formatNumber, formatPercent, formatRelative } from '../lib/format';
  import { store } from '../lib/store.svelte';

  const status = $derived(store.status);
  const blockedRatio = $derived(status && status.total_queries > 0 ? status.blocked_queries / status.total_queries : 0);
  const health = $derived([...(status?.upstream_health ?? []), ...(status?.fallback_upstream_health ?? []).map((item) => ({ ...item, fallback: true }))]);
  const security = $derived(status?.security);
  const dnssec = $derived(status?.dnssec);
</script>

<PageHeader title="仪表盘" description="DNS 请求、过滤与上游服务的实时概览。">
  {#snippet actions()}
    <button class="btn" type="button" onclick={() => store.refreshLive()}><Icon name="refresh" />刷新</button>
  {/snippet}
</PageHeader>

<section class="stats" aria-label="服务概览">
  <Stat label="累计查询" value={formatCompact(status?.total_queries ?? 0)} sub="本次启动以来" />
  <Stat label="已拦截" value={formatCompact(status?.blocked_queries ?? 0)} sub="{formatPercent(blockedRatio)} 的请求被过滤" tone="danger" />
  <Stat label="活动规则" value={formatCompact(status?.rules ?? 0)} sub="本地 {formatNumber(status?.local_rules ?? 0)} 条 · 规则源 {store.sources.filter((source) => source.enabled).length} 个" tone="ok" />
  <Stat label="平均处理时间" value={formatDuration(status?.dashboard?.average_processing_ms ?? 0)} sub="DNS 请求端到端耗时" tone="neutral" />
</section>

<Card title="请求趋势" description="最近 30 分钟每分钟的查询数与拦截数。">
  <TrafficChart points={status?.series ?? []} />
</Card>

<section class="ranks">
  <div class="col">
  <Card title="客户端" description="按请求数排序（最近日志）">
    <BarList items={status?.dashboard?.client_ips ?? []} />
  </Card>
  <Card title="被拦截域名" description="命中过滤规则最多的域名">
    <BarList items={status?.dashboard?.blocked_domains ?? []} tone="danger" empty="尚无拦截记录" />
  </Card>
  <Card title="上游服务器" description="请求数与平均响应时间">
    <BarList items={(status?.dashboard?.upstreams ?? []).map((item) => ({ name: item.address, count: item.count, note: formatDuration(item.average_duration_ms) }))} />
  </Card>
  </div>
  <div class="col">
  <Card title="请求域名" description="被查询最多的域名">
    <BarList items={status?.dashboard?.domains ?? []} />
  </Card>
  </div>
</section>

<section class="ops">
  <Card title="缓存">
    {#snippet actions()}
      <button class="btn sm" type="button" disabled={store.busy} onclick={() => store.clearCache()}>清空缓存</button>
    {/snippet}
    <dl class="kv">
      <div><dt>命中率</dt><dd>{formatPercent(status?.cache?.hit_rate ?? 0)}</dd></div>
      <div><dt>条目</dt><dd>{formatNumber(status?.cache?.entries ?? 0)}</dd></div>
      <div><dt>已用空间</dt><dd>{formatBytes(status?.cache?.used_bytes ?? 0)} / {formatBytes(status?.cache?.max_bytes ?? 0)}</dd></div>
      <div><dt>命中 / 未命中</dt><dd>{formatNumber(status?.cache?.hits ?? 0)} / {formatNumber(status?.cache?.misses ?? 0)}</dd></div>
      <div><dt>过期命中</dt><dd>{formatNumber(status?.cache?.stale_hits ?? 0)}</dd></div>
      <div><dt>淘汰 / 绕过</dt><dd>{formatNumber(status?.cache?.evictions ?? 0)} / {formatNumber(status?.cache?.bypasses ?? 0)}</dd></div>
    </dl>
  </Card>

  <Card title="上游健康">
    {#if health.length === 0}
      <p class="muted">尚未配置上游。</p>
    {:else}
      <ul class="health">
        {#each health as item (item.address + ('fallback' in item))}
          <li>
            <span class="dot" class:bad={!item.healthy} title={item.healthy ? '正常' : `连续失败 ${item.failures} 次`}></span>
            <span class="addr mono" title={item.address}>{item.address}</span>
            {#if 'fallback' in item}<span class="badge">备用</span>{/if}
            <span class="lat tabular muted">{item.requests > 0 ? formatDuration(item.latency_ms) : '—'}</span>
          </li>
        {/each}
      </ul>
      {#if health.some((item) => !item.healthy)}
        <p class="warn-note">存在连续失败的上游，会在冷却后自动重试。{formatRelative(health.find((item) => !item.healthy)?.last_failure)}最近一次失败。</p>
      {/if}
    {/if}
  </Card>

  <Card title="安全与 DNSSEC">
    <dl class="kv">
      <div><dt>拒绝的客户端</dt><dd>{formatNumber(security?.denied_clients ?? 0)}</dd></div>
      <div><dt>被限速</dt><dd>{formatNumber(security?.rate_limited ?? 0)}</dd></div>
      <div><dt>过载丢弃</dt><dd>{formatNumber(security?.overloaded ?? 0)}</dd></div>
      <div><dt>Rebinding 拦截</dt><dd>{formatNumber(security?.rebinding_blocked ?? 0)}</dd></div>
      <div><dt>DNSSEC Secure</dt><dd>{formatNumber(dnssec?.secure ?? 0)}</dd></div>
      <div><dt>DNSSEC Bogus</dt><dd>{formatNumber(dnssec?.bogus ?? 0)}</dd></div>
    </dl>
  </Card>
</section>

<style>
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
  /* Independent columns: a tall card never stretches its neighbour. */
  .ranks { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; align-items: start; }
  .col { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
  .ops { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; align-items: start; }

  .kv { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 16px; margin: 0; }
  .kv dt { color: var(--muted); font-size: 12px; }
  .kv dd { margin: 0; font-weight: 600; font-variant-numeric: tabular-nums; }

  .health { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .health li { display: flex; align-items: center; gap: 8px; }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.bad { background: var(--danger); }
  .addr { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
  .lat { font-size: 12px; }
  .warn-note { margin-top: 12px; color: var(--warn); font-size: 12px; }

  @media (max-width: 1080px) {
    .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .ops { grid-template-columns: 1fr; }
  }
  @media (max-width: 720px) {
    .ranks { grid-template-columns: 1fr; }
  }
</style>
