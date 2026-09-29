<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Field from '../components/Field.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { LocalRecord, LocalRecordType } from '../lib/types';

  const TYPES: LocalRecordType[] = ['A', 'AAAA', 'CNAME', 'TXT'];
  const PLACEHOLDERS: Record<LocalRecordType, string> = {
    A: '192.168.1.10',
    AAAA: 'fd00::10',
    CNAME: 'target.example.com',
    TXT: 'v=spf1 -all'
  };

  const blank = (): LocalRecord => ({ domain: '', type: 'A', value: '', ttl: 300 });
  let draft = $state<LocalRecord>(blank());
  let editing = $state<{ index: number; record: LocalRecord } | null>(null);
  let search = $state('');

  const records = $derived(store.saved?.local_records ?? []);
  const visible = $derived.by(() => {
    const needle = search.trim().toLowerCase();
    return records
      .map((record, index) => ({ record, index }))
      .filter(({ record }) => !needle || record.domain.toLowerCase().includes(needle) || record.value.toLowerCase().includes(needle));
  });

  function clean(record: LocalRecord): LocalRecord {
    return { domain: record.domain.trim().replace(/\.$/, ''), type: record.type, value: record.value.trim(), ttl: Math.max(0, Number(record.ttl) || 300) };
  }

  function duplicate(record: LocalRecord, except = -1) {
    return records.some(
      (item, index) => index !== except && item.domain.toLowerCase() === record.domain.toLowerCase() && item.type === record.type && item.value === record.value
    );
  }

  async function add(event: SubmitEvent) {
    event.preventDefault();
    const record = clean(draft);
    if (!record.domain || !record.value) return;
    if (duplicate(record)) {
      toasts.error('相同的记录已存在');
      return;
    }
    if (await store.saveLocalRecords([...records, record], `已添加 ${record.domain} 的 ${record.type} 记录`)) {
      draft = { ...blank(), type: record.type, ttl: record.ttl };
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault();
    if (!editing) return;
    const record = clean(editing.record);
    if (duplicate(record, editing.index)) {
      toasts.error('相同的记录已存在');
      return;
    }
    const next = records.map((item, index) => (index === editing!.index ? record : item));
    if (await store.saveLocalRecords(next, '记录已更新')) editing = null;
  }

  function remove(index: number) {
    const record = records[index];
    if (confirm(`删除 ${record.domain} 的 ${record.type} 记录？`)) {
      void store.saveLocalRecords(records.filter((_, current) => current !== index), '记录已删除');
    }
  }
</script>

<PageHeader
  title="本地记录"
  description="为内网设备或自定义域名直接应答，优先于缓存和上游（过滤规则仍先生效）。同一域名可有多条记录，修改立即生效。"
/>

<Card title="添加记录">
  <form class="add" onsubmit={add}>
    <Field label="域名"><input class="mono" placeholder="nas.home.arpa" bind:value={draft.domain} autocapitalize="off" spellcheck="false" /></Field>
    <Field label="类型">
      <select bind:value={draft.type}>{#each TYPES as type (type)}<option>{type}</option>{/each}</select>
    </Field>
    <Field label="值"><input class="mono" placeholder={PLACEHOLDERS[draft.type]} bind:value={draft.value} spellcheck="false" /></Field>
    <Field label="TTL"><div class="unit"><input type="number" min="0" bind:value={draft.ttl} /><span>秒</span></div></Field>
    <button class="btn primary" type="submit" disabled={store.busy || !draft.domain.trim() || !draft.value.trim()}><Icon name="plus" />添加</button>
  </form>
</Card>

<Card flush>
  <div class="toolbar">
    <div class="search">
      <Icon name="search" />
      <input type="search" aria-label="搜索记录" placeholder="搜索域名或值" bind:value={search} />
    </div>
    <span class="muted tabular">{records.length} 条记录</span>
  </div>
  {#if !store.saved}
    <EmptyState title="正在读取…" />
  {:else if records.length === 0}
    <EmptyState title="暂无本地记录">例如把 nas.home.arpa 指向 192.168.1.10，局域网内即可用名称访问。</EmptyState>
  {:else if visible.length === 0}
    <EmptyState title="没有匹配的记录" />
  {:else}
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th>域名</th><th>类型</th><th>值</th><th class="num">TTL</th><th></th></tr></thead>
        <tbody>
          {#each visible as { record, index } (index)}
            <tr>
              <td class="cell-domain">{record.domain}</td>
              <td><span class="badge">{record.type}</span></td>
              <td class="cell-domain">{record.value}</td>
              <td class="num muted">{record.ttl}s</td>
              <td class="end">
                <button class="btn ghost sm" type="button" disabled={store.busy} onclick={() => (editing = { index, record: { ...record } })}>编辑</button>
                <button class="btn ghost sm danger" type="button" disabled={store.busy} aria-label="删除 {record.domain}" onclick={() => remove(index)}><Icon name="trash" /></button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Card>

{#if editing}
  <Modal title="编辑记录" onclose={() => (editing = null)}>
    <form id="edit-record" class="form-grid two" onsubmit={saveEdit}>
      <Field label="域名"><input class="mono" bind:value={editing.record.domain} /></Field>
      <Field label="类型"><select bind:value={editing.record.type}>{#each TYPES as type (type)}<option>{type}</option>{/each}</select></Field>
      <Field label="值"><input class="mono" bind:value={editing.record.value} placeholder={PLACEHOLDERS[editing.record.type]} /></Field>
      <Field label="TTL（秒）"><input type="number" min="0" bind:value={editing.record.ttl} /></Field>
    </form>
    {#snippet footer()}
      <button class="btn" type="button" onclick={() => (editing = null)}>取消</button>
      <button class="btn primary" type="submit" form="edit-record" disabled={store.busy}>保存</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .add { display: grid; grid-template-columns: minmax(0, 1.4fr) 100px minmax(0, 1.6fr) 120px auto; gap: 12px; align-items: end; }
  .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 0 16px 12px; }
  .search { position: relative; flex: 0 1 320px; }
  .search :global(svg) { position: absolute; left: 10px; top: 9px; color: var(--muted); }
  .search input { padding-left: 32px; }
  .end { text-align: right; white-space: nowrap; }
  @media (max-width: 860px) {
    .add { grid-template-columns: 1fr 1fr; }
    .add > :first-child, .add > :nth-child(3) { grid-column: 1 / -1; }
  }
</style>
