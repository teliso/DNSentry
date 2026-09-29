<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Field from '../components/Field.svelte';
  import Icon from '../components/Icon.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatNumber, formatRelative } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { RuleSource } from '../lib/types';

  let url = $state('');
  let interval = $state(360);

  async function add(event: SubmitEvent) {
    event.preventDefault();
    const value = url.trim();
    if (!value) return;
    if (store.sources.some((source) => source.url === value)) {
      toasts.error('该规则源已存在');
      return;
    }
    const source: RuleSource = { url: value, enabled: true, interval_minutes: Math.max(1, Number(interval) || 360), rule_count: 0 };
    if (await store.saveSources([...store.sources, source], '规则源已添加，正在拉取')) url = '';
  }

  const toggle = (target: RuleSource, enabled: boolean) =>
    store.saveSources(store.sources.map((source) => (source.url === target.url ? { ...source, enabled } : source)), enabled ? '规则源已启用' : '规则源已停用');

  const remove = (target: RuleSource) => store.saveSources(store.sources.filter((source) => source.url !== target.url), '规则源已删除');
</script>

<PageHeader title="规则源" description="订阅 AdGuard 或 hosts 格式的在线规则。新增后会立即拉取，之后按间隔刷新；拉取失败时保留上一份成功的数据。" />

<Card title="添加规则源">
  <form class="add" onsubmit={add}>
    <Field label="列表地址">
      <input type="url" required placeholder="https://example.com/adguard.txt" bind:value={url} />
    </Field>
    <Field label="更新间隔（分钟）">
      <input type="number" min="1" bind:value={interval} />
    </Field>
    <button class="btn primary" type="submit" disabled={store.busy || !url.trim()}><Icon name="plus" />添加</button>
  </form>
</Card>

<Card title="已订阅（{store.sources.length}）" flush>
  {#if store.sources.length === 0}
    <EmptyState title="暂无远程规则源">添加一个列表地址后，它的规则会合并到过滤规则中。</EmptyState>
  {:else}
    <ul class="sources">
      {#each store.sources as source (source.url)}
        <li>
          <Switch checked={source.enabled} label={source.enabled ? '已启用' : '已停用'} disabled={store.busy} onchange={(value) => toggle(source, value)} />
          <div class="main">
            <a class="url mono" href={source.url} target="_blank" rel="noreferrer noopener" title={source.url}>{source.url}</a>
            <small class:err={source.last_error}>
              {#if source.last_error}
                <Icon name="alert" size={12} /> {source.last_error}
              {:else if source.last_updated}
                {formatRelative(source.last_updated)}更新
              {:else}
                等待首次更新
              {/if}
              · {formatNumber(source.rule_count)} 条规则 · 每 {source.interval_minutes} 分钟
            </small>
          </div>
          <button class="btn ghost sm danger" type="button" disabled={store.busy} onclick={() => remove(source)}><Icon name="trash" />删除</button>
        </li>
      {/each}
    </ul>
  {/if}
</Card>

<style>
  .add { display: grid; grid-template-columns: minmax(0, 1fr) 180px auto; gap: 12px; align-items: end; }
  .sources { list-style: none; margin: 0; padding: 0; }
  .sources li { display: flex; align-items: center; gap: 18px; padding: 14px 20px; border-top: 1px solid var(--line); }
  .sources li:first-child { border-top: 0; }
  .sources :global(.switch) { flex: none; width: 108px; }
  .main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); text-decoration: none; }
  .url:hover { text-decoration: underline; }
  small { color: var(--muted); display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
  small.err { color: var(--danger); }
  @media (max-width: 720px) {
    .add { grid-template-columns: 1fr; }
    .sources li { flex-wrap: wrap; gap: 10px 14px; padding: 14px 16px; }
    .main { flex-basis: 100%; order: 3; }
  }
</style>
