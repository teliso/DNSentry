<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { Config, LocalRecord, LocalRecordType } from '../lib/types';

  let { config }: { config: Config } = $props();

  let domain = $state('');
  let type = $state<LocalRecordType>('A');
  let value = $state('');
  let ttl = $state(300);

  const PLACEHOLDERS: Record<LocalRecordType, string> = {
    A: '192.168.1.10',
    AAAA: 'fd00::10',
    CNAME: 'target.example.com',
    TXT: 'v=spf1 -all'
  };

  function add(event: SubmitEvent) {
    event.preventDefault();
    const record: LocalRecord = { domain: domain.trim(), type, value: value.trim(), ttl: Number(ttl) || 300 };
    if (!record.domain || !record.value) return;
    const exists = config.local_records.some(
      (item) => item.domain.toLowerCase() === record.domain.toLowerCase() && item.type === record.type && item.value === record.value
    );
    if (exists) {
      toasts.error('本地记录已存在');
      return;
    }
    config.local_records.push(record);
    domain = '';
    value = '';
  }

  const remove = (index: number) => config.local_records.splice(index, 1);
</script>

<Card title="本地记录" description="本地记录优先于缓存与上游，适合内网服务与自定义域名。修改后需保存配置。">
  <div class="stack">
    <form class="add" onsubmit={add}>
      <input aria-label="域名" placeholder="nas.home.arpa" bind:value={domain} class="mono" />
      <select aria-label="记录类型" bind:value={type}>
        <option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option>
      </select>
      <input aria-label="记录值" placeholder={PLACEHOLDERS[type]} bind:value class="mono" />
      <div class="unit"><input aria-label="TTL（秒）" type="number" min="0" bind:value={ttl} /><span>秒</span></div>
      <button class="btn" type="submit" disabled={!domain.trim() || !value.trim()}><Icon name="plus" />添加</button>
    </form>

    {#if config.local_records.length === 0}
      <EmptyState title="暂无本地记录" />
    {:else}
      <div class="table-wrap bordered">
        <table class="data">
          <thead><tr><th>域名</th><th>类型</th><th>值</th><th class="num">TTL</th><th></th></tr></thead>
          <tbody>
            {#each config.local_records as record, index (record.domain + record.type + record.value)}
              <tr>
                <td class="cell-domain">{record.domain}</td>
                <td><span class="badge">{record.type}</span></td>
                <td class="cell-domain">{record.value}</td>
                <td class="num muted">{record.ttl}s</td>
                <td class="end"><button class="btn ghost sm danger" type="button" aria-label="移除 {record.domain}" onclick={() => remove(index)}><Icon name="trash" />移除</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</Card>

<style>
  .add { display: grid; grid-template-columns: minmax(0, 1.4fr) 100px minmax(0, 1.6fr) 110px auto; gap: 10px; }
  .bordered { border: 1px solid var(--line); border-radius: var(--radius-sm); }
  .end { text-align: right; }
  @media (max-width: 860px) {
    .add { grid-template-columns: 1fr 1fr; }
    .add > :first-child, .add > :nth-child(3) { grid-column: 1 / -1; }
  }
</style>
