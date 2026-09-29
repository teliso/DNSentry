<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    id,
    title,
    description,
    flush = false,
    actions,
    children
  }: { id?: string; title?: string; description?: string; flush?: boolean; actions?: Snippet; children: Snippet } = $props();
</script>

<section class="card" {id}>
  {#if title || actions}
    <header>
      <div class="heading">
        {#if title}<h2>{title}</h2>{/if}
        {#if description}<p>{description}</p>{/if}
      </div>
      {#if actions}<div class="actions">{@render actions()}</div>{/if}
    </header>
  {/if}
  <div class="body" class:flush>{@render children()}</div>
</section>

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    min-width: 0;
  }
  header {
    display: flex; align-items: flex-start; justify-content: space-between; gap: 16px;
    padding: 16px 20px 0;
  }
  .heading p { margin-top: 2px; color: var(--muted); font-size: 13px; max-width: 70ch; }
  .actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
  .body { padding: 16px 20px 20px; }
  .body.flush { padding: 12px 0 0; }
  @media (max-width: 640px) {
    header { padding: 14px 16px 0; flex-wrap: wrap; }
    .body { padding: 14px 16px 16px; }
  }
</style>
