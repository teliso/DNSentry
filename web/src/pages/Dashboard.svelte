<script lang="ts">
  import BarList from '../components/BarList.svelte';
  import Card from '../components/Card.svelte';
  import Icon from '../components/Icon.svelte';
  import LatencySpark from '../components/LatencySpark.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import ProtectionControl from '../components/ProtectionControl.svelte';
  import SetupGuide from '../components/SetupGuide.svelte';
  import Stat from '../components/Stat.svelte';
  import TrafficChart from '../components/TrafficChart.svelte';
  import { formatBytes, formatCompact, formatDuration, formatNumber, formatPercent, formatRelative } from '../lib/format';
  import { api } from '../lib/api';
  import { store } from '../lib/store.svelte';
  import type { MetricPoint } from '../lib/types';

  const status = $derived(store.status);
  const blockedRatio = $derived(status && status.total_queries > 0 ? status.blocked_queries / status.total_queries : 0);
  const health = $derived([...(status?.upstream_health ?? []), ...(status?.fallback_upstream_health ?? []).map((item) => ({ ...item, fallback: true }))]);
  const security = $derived(status?.security);
  const dnssec = $derived(status?.dnssec);
  const series = $derived(status?.series ?? []);
  let guide = $state(false);

  const RANGES = [
    { id: '30m', label: '30 分钟' },
    { id: '24h', label: '24 小时' },
    { id: '7d', label: '7 天' },
    { id: '30d', label: '30 天' },
    { id: '90d', label: '90 天' }
  ] as const;
  let range = $state<(typeof RANGES)[number]['id']>('30m');
  let longPoints = $state<MetricPoint[]>([]);
  let statsRequest = 0;
  // Longer ranges come from the persisted counters; refreshed whenever the live status moves.
  $effect(() => {
    const selected = range;
    status?.total_queries;
    if (selected === '30m') return;
    const id = ++statsRequest;
    api.stats(selected).then((points) => {
      if (id === statsRequest) longPoints = points;
    }).catch(() => {});
  });
  const trend = $derived(range === '30m' ? series : longPoints);
  const trendQueries = $derived(trend.reduce((sum, point) => sum + point.queries, 0));
  const trendBlocked = $derived(trend.reduce((sum, point) => sum + point.blocked, 0));
  /** Ranking cards stay compact; the log page has the full picture. */
  const top = <T,>(items: T[] | undefined, count = 6) => (items ?? []).slice(0, count);
</script>

<PageHeader title="概览" description="DNS 请求、过滤与上游服务的实时状态。">
  {#snippet actions()}
    <button class="btn" type="button" onclick={() => (guide = true)}><Icon name="info" />接入指引</button>
    <ProtectionControl />
    <button class="btn icon" type="button" onclick={() => store.refreshLive()} aria-label="刷新" title="刷新"><Icon name="refresh" /></button>
  {/snippet}
</PageHeader>

{#if status && status.total_queries === 0}
  <div class="callout">
    <Icon name="info" />
    <span>还没有收到任何查询。把设备的 DNS 指向 DNSentry 后，这里就会开始显示数据。</span>
    <button class="btn sm" type="button" onclick={() => (guide = true)}>查看接入指引</button>
  </div>
{/if}

<section class="stats" aria-label="服务概览">
  <Stat icon="activity" label="查询总数" value={formatCompact(status?.total_queries ?? 0)} sub="本次启动以来" spark={series.map((point) => point.queries)} />
  <Stat icon="shield" label="已拦截" tone="danger" value={formatCompact(status?.blocked_queries ?? 0)} sub="{formatPercent(blockedRatio)} 的请求被过滤" spark={series.map((point) => point.blocked)} />
  <Stat icon="check" label="缓存命中率" tone="ok" value={formatPercent(status?.cache?.hit_rate ?? 0)} sub="{formatNumber(status?.cache?.entries ?? 0)} 条 · {formatBytes(status?.cache?.used_bytes ?? 0)}" />
  <Stat icon="download" label="生效规则" tone="neutral" value={formatCompact(status?.rules ?? 0)} sub="本地 {formatNumber(status?.local_rules ?? 0)} 条 · 订阅 {store.sources.filter((source) => source.enabled).length} 个" />
</section>

<section class="trend">
  <Card title="请求趋势" description="{formatNumber(trendQueries)} 次查询，{formatNumber(trendBlocked)} 次被拦截（{formatPercent(trendQueries > 0 ? trendBlocked / trendQueries : 0)}）· 平均处理 {formatDuration(status?.dashboard?.average_processing_ms ?? 0)}">
    {#snippet actions()}
      <div class="ranges" role="group" aria-label="时间范围">
        {#each RANGES as item (item.id)}
          <button type="button" class:active={range === item.id} aria-pressed={range === item.id} onclick={() => (range = item.id)}>{item.label}</button>
        {/each}
      </div>
    {/snippet}
    <TrafficChart points={trend} {range} />
  </Card>
  <Card title="上游健康" description="最近 30 分钟的延迟；红线表示该分钟有失败">
    {#if health.length === 0}
      <p class="muted">尚未配置上游。</p>
    {:else}
      <ul class="health">
        {#each health as item (item.address + ('fallback' in item))}
          <li>
            <span class="dot" class:bad={!item.healthy} title={item.healthy ? '正常' : `连续失败 ${item.failures} 次`}></span>
            <span class="addr mono" title={item.address}>{item.address}</span>
            {#if 'fallback' in item}<span class="badge">备用</span>{/if}
            <LatencySpark points={item.history ?? []} />
          </li>
        {/each}
      </ul>
      {#if health.some((item) => !item.healthy)}
        <p class="warn-note">存在连续失败的上游，会在冷却后自动重试。{formatRelative(health.find((item) => !item.healthy)?.last_failure)}最近一次失败。</p>
      {/if}
    {/if}
  </Card>
</section>

<section class="ranks">
  <Card title="请求域名" description="被查询最多的域名">
    <BarList items={top(status?.dashboard?.domains)} />
  </Card>
  <Card title="被拦截域名" description="命中过滤规则最多的域名">
    <BarList items={top(status?.dashboard?.blocked_domains)} tone="danger" empty="尚无拦截记录" />
  </Card>
  <Card title="客户端" description="按请求数排序（最近日志）">
    <BarList items={top(status?.dashboard?.client_ips)} />
  </Card>
  <Card title="上游服务器" description="请求数与平均响应时间">
    <BarList items={(status?.dashboard?.upstreams ?? []).map((item) => ({ name: item.address, count: item.count, note: formatDuration(item.average_duration_ms) }))} />
  </Card>
  <Card title="响应最慢的域名" description="上游解析的平均耗时（最近日志）">
    <BarList items={top(status?.dashboard?.slow_domains).map((item) => ({ name: item.name, count: item.average_duration_ms, note: `${item.count} 次` }))} unit="ms" empty="暂无上游解析记录" />
  </Card>
  <Card title="解析失败的域名" description="上游无响应或返回错误">
    <BarList items={top(status?.dashboard?.failed_domains)} tone="danger" empty="没有解析失败的请求" />
  </Card>
</section>

<section class="ops">
  <Card title="缓存">
    {#snippet actions()}
      <button class="btn sm" type="button" disabled={store.busy} onclick={() => store.clearCache()}>清空缓存</button>
    {/snippet}
    <dl class="kv">
      <div><dt>命中 / 未命中</dt><dd>{formatNumber(status?.cache?.hits ?? 0)} / {formatNumber(status?.cache?.misses ?? 0)}</dd></div>
      <div><dt>已用空间</dt><dd>{formatBytes(status?.cache?.used_bytes ?? 0)} / {formatBytes(status?.cache?.max_bytes ?? 0)}</dd></div>
      <div><dt>过期命中 / 预取</dt><dd>{formatNumber(status?.cache?.stale_hits ?? 0)} / {formatNumber(status?.cache?.prefetches ?? 0)}</dd></div>
      <div><dt>淘汰 / 绕过</dt><dd>{formatNumber(status?.cache?.evictions ?? 0)} / {formatNumber(status?.cache?.bypasses ?? 0)}</dd></div>
    </dl>
  </Card>

  <Card title="安全与 DNSSEC">
    <dl class="kv">
      <div><dt>拒绝的客户端</dt><dd>{formatNumber(security?.denied_clients ?? 0)}</dd></div>
      <div><dt>被限速</dt><dd>{formatNumber(security?.rate_limited ?? 0)}</dd></div>
      <div><dt>过载丢弃</dt><dd>{formatNumber(security?.overloaded ?? 0)}</dd></div>
      <div><dt>Rebinding 拦截</dt><dd>{formatNumber(security?.rebinding_blocked ?? 0)}</dd></div>
      <div><dt>DNSSEC 已验证</dt><dd>{formatNumber(dnssec?.secure ?? 0)}</dd></div>
      <div><dt>DNSSEC 验证失败</dt><dd>{formatNumber(dnssec?.bogus ?? 0)}</dd></div>
    </dl>
  </Card>
</section>

{#if guide}<SetupGuide onclose={() => (guide = false)} />{/if}

<style>
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
  .trend { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 16px; align-items: start; }
  /* Cards size to their own content: a tall one never stretches its neighbour. */
  .ranks { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; align-items: start; }
  .ops { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; align-items: start; }

  .ranges { display: inline-flex; padding: 2px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .ranges button { padding: 3px 10px; border: 0; border-radius: 5px; background: none; color: var(--ink-2); font-size: 12px; cursor: pointer; white-space: nowrap; }
  .ranges button:hover { color: var(--ink); }
  .ranges button.active { background: var(--surface); color: var(--accent); font-weight: 600; box-shadow: var(--shadow); }

  .callout {
    display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-radius: var(--radius);
    background: var(--accent-soft); color: var(--ink-2);
  }
  .callout :global(svg) { flex: none; color: var(--accent); }
  .callout span { flex: 1; min-width: 0; }

  .kv { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 16px; margin: 0; }
  .kv dt { color: var(--muted); font-size: 12px; }
  .kv dd { margin: 0; font-weight: 600; font-variant-numeric: tabular-nums; }

  .health { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .health li { display: flex; align-items: center; gap: 8px; }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.bad { background: var(--danger); }
  .addr { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
  .warn-note { margin-top: 12px; color: var(--warn); font-size: 12px; }

  @media (max-width: 1080px) {
    .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .trend { grid-template-columns: 1fr; }
    .ranks { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 720px) {
    .ranks, .ops { grid-template-columns: 1fr; }
  }
  @media (max-width: 420px) {
    .stats { gap: 10px; }
  }
</style>
