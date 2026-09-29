<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Pager from '../components/Pager.svelte';
  import { actionInfo, formatClock, formatDuration, formatNumber } from '../lib/format';
  import { sourceName } from '../lib/rules';
  import { store } from '../lib/store.svelte';

  const PAGE_SIZE = 50;

  let query = $state('');
  let action = $state('all');
  let page = $state(1);

  const actions = $derived([...new Set(store.logs.map((entry) => entry.action))].sort());
  const filtered = $derived.by(() => {
    const needle = query.trim().toLowerCase();
    return store.logs.filter(
      (entry) => (action === 'all' || entry.action === action) && (!needle || entry.domain.includes(needle) || (entry.client ?? '').includes(needle))
    );
  });
  const visible = $derived(filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE));

  /** Actions that ended with an answer from upstream or cache, i.e. not filtered. */
  const RESOLVED = new Set(['forwarded', 'allow', 'cached', 'optimistic']);

  function quickRule(domain: string, blocked: boolean) {
    const verb = blocked ? '放行' : '拦截';
    if (confirm(`为 ${domain} 及其子域名添加${verb}规则？`)) void store.addRule(domain, blocked ? 'allow' : 'block');
  }

  $effect(() => {
    query;
    action;
    page = 1;
  });
</script>

<PageHeader title="查询日志" description="最近 {formatNumber(store.logs.length)} 条 DNS 请求（内存记录，每 10 秒自动刷新）。">
  {#snippet actions()}
    <button class="btn" type="button" onclick={() => store.refreshLive()}><Icon name="refresh" />刷新</button>
  {/snippet}
</PageHeader>

<Card flush>
  <div class="toolbar">
    <div class="search">
      <Icon name="search" />
      <input type="search" aria-label="搜索域名或客户端" placeholder="搜索域名或客户端 IP" bind:value={query} />
    </div>
    <select aria-label="按结果筛选" bind:value={action}>
      <option value="all">全部结果</option>
      {#each actions as value (value)}<option {value}>{actionInfo(value).label}</option>{/each}
    </select>
    <span class="muted tabular count">{formatNumber(filtered.length)} 条</span>
  </div>

  {#if store.logs.length === 0}
    <EmptyState title="还没有 DNS 查询记录">把设备的 DNS 指向本服务后，请求会显示在这里。</EmptyState>
  {:else if filtered.length === 0}
    <EmptyState title="没有匹配的记录" />
  {:else}
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>结果</th><th>上游</th><th class="num">耗时</th><th></th></tr></thead>
        <tbody>
          {#each visible as entry, index (entry.time + entry.domain + entry.type + index)}
            {@const info = actionInfo(entry.action)}
            <tr>
              <td class="muted tabular"><time datetime={entry.time}>{formatClock(entry.time)}</time></td>
              <td class="mono muted">{entry.client ?? '—'}</td>
              <td class="cell-domain">{entry.domain}</td>
              <td class="muted">{entry.type}</td>
              <td>
                <span class="badge {info.tone}">{info.label}</span>
                {#if entry.rule}
                  <small class="rule mono" title="来自 {sourceName(entry.rule_source, store.sources)}">{entry.rule}</small>
                {/if}
              </td>
              <td class="mono muted upstream" title={entry.upstream}>{entry.upstream ?? '—'}</td>
              <td class="num muted">{formatDuration(entry.duration_ms)}</td>
              <td class="end">
                {#if entry.action === 'block'}
                  <button class="btn ghost sm" type="button" disabled={store.busy} onclick={() => quickRule(entry.domain, true)}>放行</button>
                {:else if RESOLVED.has(entry.action) && !entry.rule}
                  <button class="btn ghost sm" type="button" disabled={store.busy} onclick={() => quickRule(entry.domain, false)}>拦截</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <Pager bind:page pageSize={PAGE_SIZE} total={filtered.length} />
  {/if}
</Card>

<style>
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 0 16px 12px; }
  .search { position: relative; flex: 1 1 240px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .toolbar select { width: auto; min-width: 150px; }
  .count { margin-left: auto; }
  .rule { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .end { text-align: right; }
  .upstream { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
