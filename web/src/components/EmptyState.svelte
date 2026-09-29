<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, children }: { title: string; children?: Snippet } = $props();
</script>

<div class="empty">
  <strong>{title}</strong>
  {#if children}<p>{@render children()}</p>{/if}
</div>

<style>
  .empty { padding: 28px 20px; text-align: center; color: var(--muted); }
  strong { display: block; color: var(--ink-2); font-weight: 500; }
  p { margin-top: 2px; font-size: 13px; }
</style>
