<script lang="ts">
  import type { Snippet } from 'svelte';

  /** The row of controls at the top of a page (the pages have no title: the navigation says where you are). */
  let { children }: { children: Snippet } = $props();
</script>

<div class="actions">{@render children()}</div>

<style>
  .actions { display: flex; align-items: center; justify-content: flex-end; gap: 8px; flex-wrap: wrap; margin-bottom: -4px; }
</style>
