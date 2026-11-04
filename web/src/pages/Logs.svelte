<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Pager from '../components/Pager.svelte';
  import Switch from '../components/Switch.svelte';
  import { api } from '../lib/api';
  import { actionInfo, formatClock, formatDuration, formatNumber } from '../lib/format';
  import { sourceName } from '../lib/rules';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { LogPage } from '../lib/types';

  const PAGE_SIZE = 50;
  const LIVE_INTERVAL_MS = 5000;
  /** Actions answered from upstream or cache without any filter rule involved. */
  const RESOLVED = new Set(['forwarded', 'cached', 'optimistic']);

  let search = $state('');
  let debounced = $state('');
  let action = $state('');
  let page = $state(1);
  let live = $state(true);
  let result = $state<LogPage | null>(null);

  $effect(() => {
    const value = search;
    const timer = window.setTimeout(() => (debounced = value.trim()), 250);
    return () => window.clearTimeout(timer);
  });
  $effect(() => {
    debounced;
    action;
    page = 1;
  });

  let request = 0;
  async function load() {
    const id = ++request;
    try {
      const next = await api.logs({ search: debounced, action, offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE });
      if (id === request) result = next;
    } catch (cause) {
      if (id === request) toasts.error(cause instanceof Error ? cause.message : '读取查询日志失败');
    }
  }

  $effect(() => {
    debounced;
    action;
    page;
    store.rulesVersion;
    void load();
  });

  // Follow new queries only on the first page, so paging back is not disturbed.
  onMount(() => {
    const timer = window.setInterval(() => {
      if (live && page === 1 && !document.hidden) void load();
    }, LIVE_INTERVAL_MS);
    return () => window.clearInterval(timer);
  });

  function quickRule(domain: string, allow: boolean) {
    if (confirm(`为 ${domain} 及其子域名添加${allow ? '放行' : '拦截'}规则？`)) void store.addRule(domain, allow ? 'allow' : 'block');
  }
</script>

<PageHeader title="查询日志" description="最近的 DNS 请求及其处理结果（内存中保留最近 {formatNumber(store.saved?.query_log_size ?? 0)} 条）。">
  {#snippet actions()}
    <Switch bind:checked={live} label="实时刷新" />
    <button class="btn" type="button" onclick={load}><Icon name="refresh" />刷新</button>
  {/snippet}
</PageHeader>

<Card flush>
  <div class="toolbar">
    <div class="search">
      <Icon name="search" />
      <input type="search" aria-label="搜索域名或客户端" placeholder="搜索域名或客户端 IP" bind:value={search} />
    </div>
    <select aria-label="按结果筛选" bind:value={action}>
      <option value="">全部结果</option>
      {#each result?.actions ?? [] as value (value)}<option {value}>{actionInfo(value).label}</option>{/each}
    </select>
    <span class="muted tabular count">{formatNumber(result?.total ?? 0)} 条</span>
  </div>

  {#if !result}
    <EmptyState title="正在读取…" />
  {:else if result.total === 0}
    {#if debounced || action}
      <EmptyState title="没有匹配的记录" />
    {:else}
      <EmptyState title="还没有 DNS 查询记录">把设备的 DNS 指向本服务后，请求会显示在这里。</EmptyState>
    {/if}
  {:else}
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>结果</th><th>上游</th><th class="num">耗时</th><th></th></tr></thead>
        <tbody>
          {#each result.items as entry, index (entry.time + entry.domain + entry.type + index)}
            {@const info = actionInfo(entry.action)}
            <tr>
              <td class="muted tabular"><time datetime={entry.time}>{formatClock(entry.time)}</time></td>
              <td><button class="link mono" type="button" title="只看该客户端" onclick={() => (search = entry.client ?? '')}>{entry.client ?? '—'}</button></td>
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
    <Pager bind:page pageSize={PAGE_SIZE} total={result.total} />
  {/if}
</Card>

<style>
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 0 16px 12px; }
  .search { position: relative; flex: 1 1 240px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .toolbar select { width: auto; min-width: 150px; }
  .count { margin-left: auto; }
  .link { border: 0; padding: 0; background: none; color: var(--muted); cursor: pointer; font-size: 13px; }
  .link:hover { color: var(--accent); text-decoration: underline; }
  .rule { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .upstream { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .end { text-align: right; }
</style>
