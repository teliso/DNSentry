<script lang="ts">
  import BarList from '../components/BarList.svelte';
  import Card from '../components/Card.svelte';
  import Icon from '../components/Icon.svelte';
  import LatencySpark from '../components/LatencySpark.svelte';
  import PageActions from '../components/PageActions.svelte';
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
  /** Average answer time per upstream, from the recent log. */
  const averages = $derived(new Map((status?.dashboard?.upstreams ?? []).map((item) => [item.address, item.average_duration_ms])));
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

<PageActions>
  <button class="btn" type="button" onclick={() => (guide = true)}><Icon name="info" />接入指引</button>
  <ProtectionControl />
  <button class="btn icon" type="button" onclick={() => store.refreshLive()} aria-label="刷新" title="刷新"><Icon name="refresh" /></button>
</PageActions>

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

  <Card title="上游服务器" description="最近 30 分钟的延迟；红线表示该分钟有失败" scroll>
    {#if health.length === 0}
      <p class="muted">尚未配置上游。</p>
    {:else}
      <ul class="health">
        {#each health as item (item.address + ('fallback' in item))}
          <li>
            <span class="dot" class:bad={!item.healthy} title={item.healthy ? '正常' : `连续失败 ${item.failures} 次`}></span>
            <div class="info">
              <span class="addr mono" title={item.address}>{item.address}{#if 'fallback' in item}<span class="badge">备用</span>{/if}</span>
              <small class="muted tabular">
                {formatNumber(item.requests)} 次请求 · {averages.has(item.address) ? `平均 ${formatDuration(averages.get(item.address) ?? 0)}` : `延迟 ${formatDuration(item.latency_ms)}`}{#if !item.healthy} · <span class="bad-text">冷却中，{formatRelative(item.last_failure)}失败</span>{/if}
              </small>
            </div>
            <LatencySpark points={item.history ?? []} />
          </li>
        {/each}
      </ul>
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
  <Card title="响应最慢的域名" description="上游解析的平均耗时（最近日志）">
    <BarList items={top(status?.dashboard?.slow_domains).map((item) => ({ name: item.name, count: item.average_duration_ms, note: `${item.count} 次` }))} unit="ms" empty="暂无上游解析记录" />
  </Card>
  <Card title="解析失败的域名" description="上游无响应或返回错误">
    <BarList items={top(status?.dashboard?.failed_domains)} tone="danger" empty="没有解析失败的请求" />
  </Card>
  <Card title="运行状态" description="缓存、访问控制与 DNSSEC">
    <dl class="kv">
      <div><dt>缓存 命中 / 未命中</dt><dd>{formatNumber(status?.cache?.hits ?? 0)} / {formatNumber(status?.cache?.misses ?? 0)}</dd></div>
      <div><dt>缓存占用</dt><dd>{formatBytes(status?.cache?.used_bytes ?? 0)} / {formatBytes(status?.cache?.max_bytes ?? 0)}</dd></div>
      <div><dt>过期命中 / 预取</dt><dd>{formatNumber(status?.cache?.stale_hits ?? 0)} / {formatNumber(status?.cache?.prefetches ?? 0)}</dd></div>
      <div><dt>淘汰 / 绕过</dt><dd>{formatNumber(status?.cache?.evictions ?? 0)} / {formatNumber(status?.cache?.bypasses ?? 0)}</dd></div>
      <div><dt>拒绝的客户端</dt><dd>{formatNumber(security?.denied_clients ?? 0)}</dd></div>
      <div><dt>被限速 / 过载</dt><dd>{formatNumber(security?.rate_limited ?? 0)} / {formatNumber(security?.overloaded ?? 0)}</dd></div>
      <div><dt>Rebinding 拦截</dt><dd>{formatNumber(security?.rebinding_blocked ?? 0)}</dd></div>
      <div><dt>DNSSEC 已验证 / 失败</dt><dd>{formatNumber(dnssec?.secure ?? 0)} / {formatNumber(dnssec?.bogus ?? 0)}</dd></div>
    </dl>
  </Card>
</section>

{#if guide}<SetupGuide onclose={() => (guide = false)} />{/if}

<style>
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
  /* The upstream card takes the height of the chart card and scrolls. */
  .trend { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 16px; align-items: stretch; }
  .trend > :global(.card.fill) { min-height: 0; max-height: 380px; }
  /* Every ranking card gets the same size, so the grid reads as a tidy table of tiles. */
  .ranks { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); grid-auto-rows: 1fr; gap: 16px; }

  .callout {
    display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-radius: var(--radius);
    background: var(--accent-soft); color: var(--ink-2);
  }
  .callout :global(svg) { flex: none; color: var(--accent); }
  .callout span { flex: 1; min-width: 0; }

  .ranges { display: inline-flex; padding: 2px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .ranges button { padding: 3px 10px; border: 0; border-radius: 5px; background: none; color: var(--ink-2); font-size: 12px; cursor: pointer; white-space: nowrap; }
  .ranges button:hover { color: var(--ink); }
  .ranges button.active { background: var(--surface); color: var(--accent); font-weight: 600; box-shadow: var(--shadow); }

  .kv { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 16px; margin: 0; }
  .kv dt { color: var(--muted); font-size: 12px; }
  .kv dd { margin: 0; font-weight: 600; font-variant-numeric: tabular-nums; }

  .health { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 14px; }
  .health li { display: flex; align-items: center; gap: 10px; }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.bad { background: var(--danger); }
  .info { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .addr { display: flex; align-items: center; gap: 6px; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .info small { font-size: 12px; }
  .bad-text { color: var(--danger); }

  @media (max-width: 1080px) {
    .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .trend { grid-template-columns: 1fr; }
    .trend > :global(.card.fill) { max-height: 320px; }
    .ranks { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 720px) {
    .ranks { grid-template-columns: 1fr; grid-auto-rows: auto; }
  }
  @media (max-width: 420px) {
    .stats { gap: 10px; }
  }
</style>
