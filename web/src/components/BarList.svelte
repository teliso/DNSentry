<script lang="ts">
  import { formatNumber } from '../lib/format';

  type Item = { name: string; count: number; note?: string };
  let { items, empty = '暂无数据', tone = 'accent' }: { items: Item[]; empty?: string; tone?: 'accent' | 'danger' } = $props();

  const max = $derived(Math.max(1, ...items.map((item) => item.count)));
</script>

{#if items.length === 0}
  <p class="empty">{empty}</p>
{:else}
  <ol>
    {#each items as item (item.name)}
      <li>
        <div class="row">
          <span class="name" title={item.name}>{item.name}</span>
          {#if item.note}<span class="note tabular">{item.note}</span>{/if}
          <span class="count tabular">{formatNumber(item.count)}</span>
        </div>
        <div class="bar"><span class={tone} style:width="{Math.max(2, (item.count / max) * 100)}%"></span></div>
      </li>
    {/each}
  </ol>
{/if}

<style>
  ol { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 11px; }
  .row { display: flex; align-items: baseline; gap: 10px; }
  .name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: 13px; }
  .note { color: var(--muted); font-size: 12px; }
  .count { font-weight: 600; }
  .bar { height: 4px; margin-top: 5px; border-radius: 2px; background: var(--surface-2); overflow: hidden; }
  .bar span { display: block; height: 100%; border-radius: 2px; background: var(--series-total); }
  .bar span.danger { background: var(--series-blocked); }
  .empty { color: var(--muted); padding: 18px 0; text-align: center; }
</style>
