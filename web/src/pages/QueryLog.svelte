<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageActions from '../components/PageActions.svelte';
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
  /** A saved day (YYYY-MM-DD) being browsed, or '' for the live in-memory log. */
  let day = $state('');
  let days = $state<string[]>([]);
  const browsing = $derived(day !== '');

  async function loadDays() {
    try {
      days = (await api.logDays()).days;
    } catch {
      days = [];
    }
  }
  void loadDays();

  $effect(() => {
    const value = search;
    const timer = window.setTimeout(() => (debounced = value.trim()), 250);
    return () => window.clearTimeout(timer);
  });
  $effect(() => {
    debounced;
    action;
    day;
    page = 1;
  });

  let request = 0;
  async function load() {
    const id = ++request;
    try {
      const next = await api.logs({ search: debounced, action, date: day, offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE });
      if (id === request) result = next;
    } catch (cause) {
      if (id === request) toasts.error(cause instanceof Error ? cause.message : '读取查询日志失败');
    }
  }

  $effect(() => {
    debounced;
    action;
    day;
    page;
    store.rulesVersion;
    void load();
  });

  // Follow new queries only on the first page, so paging back is not disturbed.
  onMount(() => {
    const timer = window.setInterval(() => {
      if (live && !browsing && page === 1 && !document.hidden) void load();
    }, LIVE_INTERVAL_MS);
    return () => window.clearInterval(timer);
  });

  async function exportLogs() {
    try {
      await api.exportLogs('csv', { search: debounced, action, date: day });
    } catch (cause) {
      toasts.error(cause instanceof Error ? cause.message : '导出失败');
    }
  }

  function quickRule(domain: string, allow: boolean) {
    if (confirm(`为 ${domain} 及其子域名添加${allow ? '放行' : '拦截'}规则？`)) void store.addRule(domain, allow ? 'allow' : 'block');
  }
</script>

<PageActions>
  {#if days.length > 0}
    <select class="day" aria-label="查看哪一天的日志" bind:value={day}>
      <option value="">最近（内存）</option>
      {#each days as value (value)}<option {value}>{value}</option>{/each}
    </select>
  {/if}
  {#if !browsing}<Switch bind:checked={live} label="实时刷新" />{/if}
  <button class="btn icon" type="button" onclick={load} aria-label="刷新" title="刷新"><Icon name="refresh" /></button>
  <button class="btn icon" type="button" onclick={exportLogs} aria-label="导出 CSV" title="导出当前筛选条件下的全部日志（CSV，可用 Excel 打开）"><Icon name="download" /></button>
</PageActions>

{#if result?.truncated}
  <p class="warning">这一天的匹配记录太多，只显示最新的 20 万条。可以用搜索或结果筛选缩小范围。</p>
{/if}

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
  .day { width: auto; }
  .warning { padding: 9px 12px; border-radius: var(--radius-sm); background: var(--warn-soft); color: var(--ink-2); }
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
