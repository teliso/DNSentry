<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Pager from '../components/Pager.svelte';
  import { formatNumber } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import type { RuleAction } from '../lib/types';

  const PAGE_SIZE = 50;
  const ACTION_LABEL: Record<string, string> = { block: '拦截', allow: '放行', rewrite: '改写' };

  let domain = $state('');
  let action = $state<RuleAction>('block');
  let query = $state('');
  let filter = $state<'all' | 'block' | 'allow' | 'remote'>('all');
  let page = $state(1);

  const filtered = $derived.by(() => {
    const needle = query.trim().toLowerCase();
    return store.rules.filter((rule) => {
      if (filter === 'remote' ? !rule.source : filter !== 'all' && rule.action !== filter) return false;
      return !needle || rule.domain.includes(needle);
    });
  });
  const visible = $derived(filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE));
  const remoteCount = $derived(store.rules.reduce((count, rule) => count + (rule.source ? 1 : 0), 0));

  $effect(() => {
    query;
    filter;
    page = 1;
  });

  onMount(() => {
    void store.loadRules();
  });

  async function add(event: SubmitEvent) {
    event.preventDefault();
    const value = domain.trim();
    if (value && (await store.addRule(value, action))) domain = '';
  }

  function sourceLabel(source: string): string {
    try {
      return new URL(source).host;
    } catch {
      return source;
    }
  }
</script>

<PageHeader title="过滤规则" description="支持 example.com 与 AdGuard 的 ||domain.example^ 语法；放行规则优先于拦截规则，并覆盖其子域名。">
  {#snippet actions()}
    <button class="btn" type="button" disabled={store.busy} onclick={() => store.reloadRules()}><Icon name="refresh" />重新载入本地规则</button>
  {/snippet}
</PageHeader>

<Card title="添加规则">
  <form class="add" onsubmit={add}>
    <input aria-label="域名" placeholder="ads.example.com" bind:value={domain} autocapitalize="off" spellcheck="false" />
    <select aria-label="动作" bind:value={action}>
      <option value="block">拦截</option>
      <option value="allow">放行</option>
    </select>
    <button class="btn primary" type="submit" disabled={store.busy || !domain.trim()}><Icon name="plus" />添加</button>
  </form>
</Card>

<Card flush>
  <div class="toolbar">
    <div class="search">
      <Icon name="search" />
      <input type="search" aria-label="搜索域名" placeholder="搜索域名" bind:value={query} />
    </div>
    <select aria-label="按类型筛选" bind:value={filter}>
      <option value="all">全部（{formatNumber(store.rules.length)}）</option>
      <option value="block">仅拦截</option>
      <option value="allow">仅放行</option>
      <option value="remote">来自规则源（{formatNumber(remoteCount)}）</option>
    </select>
    <span class="muted tabular count">{formatNumber(filtered.length)} 条</span>
  </div>

  {#if !store.rulesLoaded}
    <EmptyState title="正在读取规则…" />
  {:else if filtered.length === 0}
    <EmptyState title={store.rules.length === 0 ? '暂无规则' : '没有匹配的规则'}>
      {store.rules.length === 0 ? '添加第一条规则，或在“规则源”中订阅在线列表。' : '换个关键词或筛选条件试试。'}
    </EmptyState>
  {:else}
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th>域名</th><th>动作</th><th>来源</th><th></th></tr></thead>
        <tbody>
          {#each visible as rule (rule.domain + rule.action + (rule.source ?? ''))}
            <tr>
              <td class="cell-domain">{rule.domain}{#if rule.ip}<span class="muted"> → {rule.ip}</span>{/if}</td>
              <td><span class="badge" class:danger={rule.action === 'block'} class:ok={rule.action === 'allow'} class:accent={rule.action === 'rewrite'}>{ACTION_LABEL[rule.action] ?? rule.action}</span></td>
              <td class="muted" title={rule.source}>{rule.source ? sourceLabel(rule.source) : '本地规则'}</td>
              <td class="end">
                {#if !rule.source}
                  <button class="btn ghost sm danger" type="button" disabled={store.busy} aria-label="删除 {rule.domain}" onclick={() => store.removeRule(rule)}><Icon name="trash" />删除</button>
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
  .add { display: grid; grid-template-columns: minmax(0, 1fr) 120px auto; gap: 10px; }
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 0 16px 12px; }
  .search { position: relative; flex: 1 1 220px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .toolbar select { width: auto; min-width: 160px; }
  .count { margin-left: auto; }
  .end { text-align: right; }
  @media (max-width: 640px) {
    .add { grid-template-columns: 1fr 1fr; }
    .add input { grid-column: 1 / -1; }
  }
</style>
