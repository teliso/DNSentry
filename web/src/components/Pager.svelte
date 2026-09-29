<script lang="ts">
  import Icon from './Icon.svelte';

  let { page = $bindable(1), pageSize, total }: { page?: number; pageSize: number; total: number } = $props();
  const pages = $derived(Math.max(1, Math.ceil(total / pageSize)));
  $effect(() => {
    if (page > pages) page = pages;
  });
</script>

{#if total > pageSize}
  <nav class="pager" aria-label="分页">
    <span class="muted tabular">第 {page} / {pages} 页 · 共 {total.toLocaleString('zh-CN')} 条</span>
    <div>
      <button class="btn sm icon" type="button" aria-label="上一页" disabled={page <= 1} onclick={() => page--}><Icon name="chevron-left" /></button>
      <button class="btn sm icon" type="button" aria-label="下一页" disabled={page >= pages} onclick={() => page++}><Icon name="chevron" /></button>
    </div>
  </nav>
{/if}

<style>
  .pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 16px; border-top: 1px solid var(--line); }
  div { display: flex; gap: 6px; }
</style>
