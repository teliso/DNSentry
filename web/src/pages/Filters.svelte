<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Pager from '../components/Pager.svelte';
  import RuleCheck from '../components/RuleCheck.svelte';
  import LocalRulesEditor from '../sections/LocalRulesEditor.svelte';
  import { api } from '../lib/api';
  import { formatNumber } from '../lib/format';
  import { ruleText, sourceName } from '../lib/rules';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { Rule, RuleAction, RulePage } from '../lib/types';

  const PAGE_SIZE = 50;

  let domain = $state('');
  let action = $state<RuleAction>('block');
  let editing = $state(false);

  let search = $state('');
  let debouncedSearch = $state('');
  let actionFilter = $state<RuleAction | ''>('');
  let source = $state(store.ruleSourceFilter);
  let page = $state(1);
  let result = $state<RulePage | null>(null);

  // A filter handed over from the sources page applies once.
  store.ruleSourceFilter = '';

  $effect(() => {
    const value = search;
    const timer = window.setTimeout(() => (debouncedSearch = value.trim()), 250);
    return () => window.clearTimeout(timer);
  });

  $effect(() => {
    debouncedSearch;
    actionFilter;
    source;
    page = 1;
  });

  let request = 0;
  $effect(() => {
    const query = { search: debouncedSearch, action: actionFilter, source, offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE };
    store.rulesVersion;
    const id = ++request;
    api
      .rules(query)
      .then((next) => {
        if (id === request) result = next;
      })
      .catch((cause) => toasts.error(cause instanceof Error ? cause.message : '读取规则失败'));
  });

  async function add(event: SubmitEvent) {
    event.preventDefault();
    if (domain.trim() && (await store.addRule(domain.trim(), action))) domain = '';
  }

  const remove = (rule: Rule) => store.removeRule(rule);
</script>

<PageHeader title="过滤规则" description="本地规则保存在 rules.txt，优先于规则源；同一来源内放行规则优先于拦截规则，并覆盖其子域名。">
  {#snippet actions()}
    <button class="btn" type="button" disabled={store.busy} onclick={() => store.reloadRules()} title="文件在外部被修改后使用">
      <Icon name="refresh" />从磁盘重新载入
    </button>
    <button class="btn" type="button" onclick={() => (editing = !editing)}>
      <Icon name={editing ? 'list' : 'settings'} />{editing ? '返回规则列表' : '编辑 rules.txt'}
    </button>
  {/snippet}
</PageHeader>

{#if editing}
  <LocalRulesEditor onclose={() => (editing = false)} />
{:else}
  <div class="top">
    <RuleCheck />
    <Card title="添加本地规则" description="域名会同时匹配其所有子域名。">
      <form class="add" onsubmit={add}>
        <input aria-label="域名" placeholder="ads.example.com 或 ||ads.example.com^" bind:value={domain} autocapitalize="off" spellcheck="false" />
        <select aria-label="动作" bind:value={action}>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
        </select>
        <button class="btn primary" type="submit" disabled={store.busy || !domain.trim()}><Icon name="plus" />添加</button>
      </form>
    </Card>
  </div>

  <Card flush>
    <div class="toolbar">
      <div class="search">
        <Icon name="search" />
        <input type="search" aria-label="搜索域名" placeholder="搜索域名" bind:value={search} />
      </div>
      <select aria-label="按来源筛选" bind:value={source}>
        <option value="">全部来源</option>
        <option value="local">本地规则（{formatNumber(store.status?.local_rules ?? 0)}）</option>
        {#each store.sources as item (item.url)}
          <option value={item.url}>{sourceName(item.url, store.sources)}（{formatNumber(item.rule_count ?? 0)}）</option>
        {/each}
      </select>
      <select aria-label="按动作筛选" bind:value={actionFilter}>
        <option value="">全部动作</option>
        <option value="block">拦截</option>
        <option value="allow">放行</option>
      </select>
      <span class="muted tabular count">{formatNumber(result?.total ?? 0)} 条</span>
    </div>

    {#if !result}
      <EmptyState title="正在读取规则…" />
    {:else if result.total === 0}
      <EmptyState title={debouncedSearch || actionFilter || source ? '没有匹配的规则' : '暂无规则'}>
        {debouncedSearch || actionFilter || source ? '换个关键词或筛选条件试试。' : '添加第一条规则，或在“规则源”中订阅在线列表。'}
      </EmptyState>
    {:else}
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>规则</th><th>动作</th><th>来源</th><th></th></tr></thead>
          <tbody>
            {#each result.items as rule, index (index + rule.domain + rule.action + (rule.source ?? ''))}
              <tr>
                <td class="cell-domain">{ruleText(rule)}</td>
                <td><span class="badge" class:danger={rule.action === 'block'} class:ok={rule.action === 'allow'}>{rule.action === 'allow' ? '放行' : '拦截'}</span></td>
                <td class="muted source" title={rule.source}>{rule.source ? sourceName(rule.source, store.sources) : '本地规则'}</td>
                <td class="end">
                  {#if !rule.source}
                    <button class="btn ghost sm danger" type="button" disabled={store.busy} aria-label="删除 {rule.domain}" onclick={() => remove(rule)}><Icon name="trash" />删除</button>
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
{/if}

<style>
  .top { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; align-items: start; }
  .add { display: grid; grid-template-columns: minmax(0, 1fr) 100px auto; gap: 10px; }
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 0 16px 12px; }
  .search { position: relative; flex: 1 1 200px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .toolbar select { width: auto; max-width: 240px; }
  .count { margin-left: auto; }
  .source { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .end { text-align: right; }
  @media (max-width: 960px) { .top { grid-template-columns: 1fr; } }
  @media (max-width: 640px) {
    .add { grid-template-columns: 1fr 1fr; }
    .add input { grid-column: 1 / -1; }
  }
</style>
