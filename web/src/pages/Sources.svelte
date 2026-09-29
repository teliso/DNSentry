<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Field from '../components/Field.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatNumber, formatRelative } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import { hostOf } from '../lib/rules';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { RuleSource } from '../lib/types';

  const INTERVALS = [
    { minutes: 60, label: '每小时' },
    { minutes: 360, label: '每 6 小时' },
    { minutes: 720, label: '每 12 小时' },
    { minutes: 1440, label: '每天' },
    { minutes: 10080, label: '每周' }
  ];

  let url = $state('');
  let name = $state('');
  let interval = $state(360);
  let editing = $state<RuleSource | null>(null);

  const enabledCount = $derived(store.sources.filter((source) => source.enabled).length);
  const totalRules = $derived(store.sources.reduce((sum, source) => sum + (source.rule_count ?? 0), 0));
  const anyUpdating = $derived(store.sources.some((source) => source.updating));

  function intervalLabel(minutes: number) {
    return INTERVALS.find((item) => item.minutes === minutes)?.label ?? `每 ${minutes} 分钟`;
  }

  async function add(event: SubmitEvent) {
    event.preventDefault();
    const value = url.trim();
    if (store.sources.some((source) => source.url === value)) {
      toasts.error('该规则源已存在');
      return;
    }
    const source: RuleSource = { url: value, name: name.trim(), enabled: true, interval_minutes: interval };
    if (await store.saveSources([...store.sources, source], '规则源已添加，正在下载')) {
      url = '';
      name = '';
    }
  }

  const replace = (target: string, change: Partial<RuleSource>, done: string) =>
    store.saveSources(store.sources.map((source) => (source.url === target ? { ...source, ...change } : source)), done);

  function remove(source: RuleSource) {
    if (confirm(`删除规则源“${source.name || hostOf(source.url)}”？它的 ${source.rule_count ?? 0} 条规则和本地缓存会一并移除。`)) {
      void store.saveSources(store.sources.filter((item) => item.url !== source.url), '规则源已删除');
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault();
    if (!editing) return;
    const { url: target, name: nextName, interval_minutes } = editing;
    if (await replace(target, { name: nextName?.trim(), interval_minutes: Number(interval_minutes) || 360 }, '规则源已更新')) editing = null;
  }

  function viewRules(source: RuleSource) {
    store.ruleSourceFilter = source.url;
    router.go('filters');
  }
</script>

<PageHeader title="规则源" description="订阅 AdGuard 或 hosts 格式的在线规则列表。下载的列表缓存在本地，重启后立即生效；更新失败时继续使用上一次成功的版本。">
  {#snippet actions()}
    <button class="btn" type="button" disabled={store.busy || anyUpdating || enabledCount === 0} onclick={() => store.refreshSources()}>
      <Icon name="refresh" />全部更新
    </button>
  {/snippet}
</PageHeader>

<Card title="添加规则源">
  <form class="add" onsubmit={add}>
    <Field label="列表地址">
      <input type="url" required placeholder="https://example.com/filter.txt" bind:value={url} />
    </Field>
    <Field label="名称（可选）">
      <input placeholder="广告过滤" maxlength="64" bind:value={name} />
    </Field>
    <Field label="更新频率">
      <select bind:value={interval}>
        {#each INTERVALS as item (item.minutes)}<option value={item.minutes}>{item.label}</option>{/each}
      </select>
    </Field>
    <button class="btn primary" type="submit" disabled={store.busy || !url.trim()}><Icon name="plus" />添加</button>
  </form>
</Card>

<Card title="已订阅" description="{store.sources.length} 个规则源，{enabledCount} 个启用，共 {formatNumber(totalRules)} 条规则生效。" flush>
  {#if store.sources.length === 0}
    <EmptyState title="暂无远程规则源">添加一个列表地址后，它的规则会合并到过滤规则中。</EmptyState>
  {:else}
    <ul class="sources">
      {#each store.sources as source (source.url)}
        <li class:disabled={!source.enabled}>
          <Switch
            checked={source.enabled}
            label={source.enabled ? '启用' : '停用'}
            disabled={store.busy}
            onchange={(enabled) => replace(source.url, { enabled }, enabled ? '规则源已启用' : '规则源已停用，其规则不再生效')}
          />
          <div class="main">
            <div class="title">
              <strong>{source.name || hostOf(source.url)}</strong>
              {#if source.updating}<span class="badge accent">更新中…</span>{/if}
            </div>
            <a class="url mono" href={source.url} target="_blank" rel="noreferrer noopener" title={source.url}>{source.url}</a>
            <small>
              {#if source.enabled}{formatNumber(source.rule_count ?? 0)} 条规则 · {/if}{intervalLabel(source.interval_minutes)}更新
              {#if source.last_updated}· 内容更新于 {formatRelative(source.last_updated)}{/if}
              {#if source.last_checked && source.last_checked !== source.last_updated}· 检查于 {formatRelative(source.last_checked)}{/if}
              {#if !source.last_updated && !source.last_error && source.enabled}· 等待首次下载{/if}
            </small>
            {#if source.last_error}
              <small class="err"><Icon name="alert" size={12} />上次更新失败：{source.last_error}{source.rule_count ? '（继续使用缓存的规则）' : ''}</small>
            {/if}
          </div>
          <div class="actions">
            <button class="btn ghost sm" type="button" disabled={!source.enabled || source.updating || store.busy} onclick={() => store.refreshSources(source.url)} title="立即更新">
              <Icon name="refresh" /><span class="label">更新</span>
            </button>
            <button class="btn ghost sm" type="button" disabled={!source.enabled || !source.rule_count} onclick={() => viewRules(source)} title="查看规则">
              <Icon name="list" /><span class="label">规则</span>
            </button>
            <button class="btn ghost sm" type="button" disabled={store.busy} onclick={() => (editing = { ...source })} title="编辑">
              <Icon name="settings" /><span class="label">编辑</span>
            </button>
            <button class="btn ghost sm danger" type="button" disabled={store.busy} onclick={() => remove(source)} title="删除">
              <Icon name="trash" /><span class="label">删除</span>
            </button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</Card>

{#if editing}
  <Modal title="编辑规则源" onclose={() => (editing = null)}>
    <form id="edit-source" class="stack" onsubmit={saveEdit}>
      <Field label="列表地址"><input class="mono" value={editing.url} disabled /></Field>
      <Field label="名称"><input maxlength="64" placeholder={hostOf(editing.url)} bind:value={editing.name} /></Field>
      <Field label="更新频率" hint="也可以填写 1–43200 之间的分钟数">
        <div class="unit"><input type="number" min="1" max="43200" bind:value={editing.interval_minutes} /><span>分钟</span></div>
      </Field>
    </form>
    {#snippet footer()}
      <button class="btn" type="button" onclick={() => (editing = null)}>取消</button>
      <button class="btn primary" type="submit" form="edit-source" disabled={store.busy}>保存</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .add { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) 140px auto; gap: 12px; align-items: end; }
  .sources { list-style: none; margin: 0; padding: 0; }
  .sources li { display: flex; align-items: center; gap: 18px; padding: 14px 20px; border-top: 1px solid var(--line); }
  .sources li:first-child { border-top: 0; }
  .sources li.disabled .main { opacity: 0.6; }
  .sources :global(.switch) { flex: none; width: 80px; }
  .main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .title { display: flex; align-items: center; gap: 8px; }
  .url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: 12px; text-decoration: none; }
  .url:hover { text-decoration: underline; }
  small { color: var(--muted); }
  small.err { color: var(--danger); display: flex; align-items: center; gap: 4px; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 2px; flex: none; }
  @media (max-width: 860px) {
    .add { grid-template-columns: 1fr 1fr; }
    .add > :first-child { grid-column: 1 / -1; }
    .sources li { flex-wrap: wrap; gap: 10px 14px; padding: 14px 16px; }
    .main { flex-basis: 100%; order: 3; }
    .actions { margin-left: auto; }
    .label { display: none; }
  }
</style>
