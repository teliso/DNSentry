<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageActions from '../components/PageActions.svelte';
  import Switch from '../components/Switch.svelte';
  import { api } from '../lib/api';
  import { formatClock } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { ProgramLogs } from '../lib/types';

  let level = $state('info');
  let search = $state('');
  let debounced = $state('');
  let live = $state(true);
  let result = $state<ProgramLogs | null>(null);

  $effect(() => {
    const value = search;
    const timer = window.setTimeout(() => (debounced = value.trim()), 250);
    return () => window.clearTimeout(timer);
  });

  let request = 0;
  async function load() {
    const id = ++request;
    try {
      const next = await api.programLogs({ level, search: debounced });
      if (id === request) result = next;
    } catch (cause) {
      if (id === request) toasts.error(cause instanceof Error ? cause.message : '读取程序日志失败');
    }
  }

  $effect(() => {
    level;
    debounced;
    void load();
  });

  onMount(() => {
    const timer = window.setInterval(() => {
      if (live && !document.hidden) void load();
    }, 5000);
    return () => window.clearInterval(timer);
  });
</script>

<PageActions>
  <Switch bind:checked={live} label="实时刷新" />
  <button class="btn icon" type="button" onclick={load} aria-label="刷新" title="刷新"><Icon name="refresh" /></button>
</PageActions>

<Card flush>
  <div class="toolbar">
    <div class="search">
      <Icon name="search" />
      <input type="search" aria-label="搜索日志" placeholder="搜索日志内容" bind:value={search} />
    </div>
    <select aria-label="最低级别" bind:value={level}>
      <option value="debug">调试及以上</option>
      <option value="info">信息及以上</option>
      <option value="warn">警告及以上</option>
      <option value="error">仅错误</option>
    </select>
  </div>

  {#if !result}
    <EmptyState title="正在读取…" />
  {:else if result.level === 'off' && result.entries.length === 0}
    <EmptyState title="程序日志已关闭">在“设置 → 日志”里选择记录级别后，程序运行信息会显示在这里。<a href={router.href('settings/logging')}>前往设置</a></EmptyState>
  {:else if result.entries.length === 0}
    <EmptyState title="没有匹配的日志" />
  {:else}
    <ul class="lines">
      {#each result.entries as entry, index (entry.time + index)}
        <li>
          <time class="muted tabular" datetime={entry.time}>{formatClock(entry.time)}</time>
          <span class="badge lv {entry.level}">{entry.level}</span>
          <span class="msg">{entry.message}{#if entry.attrs}<small class="mono muted"> {entry.attrs}</small>{/if}</span>
        </li>
      {/each}
    </ul>
  {/if}
</Card>

<style>
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 0 16px 12px; }
  .search { position: relative; flex: 1 1 240px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .toolbar select { width: auto; min-width: 150px; }
  .lines { list-style: none; margin: 0; padding: 0; font-size: 13px; }
  li { display: flex; align-items: baseline; gap: 10px; padding: 7px 16px; border-top: 1px solid var(--line); }
  .lv { flex: none; width: 52px; justify-content: center; text-transform: uppercase; font-size: 10px; }
  .lv.warn { background: var(--warn-soft); color: var(--warn); }
  .lv.error { background: var(--danger-soft); color: var(--danger); }
  .msg { min-width: 0; overflow-wrap: anywhere; }
  .msg small { font-size: 12px; }
</style>
