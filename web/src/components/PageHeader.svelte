<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, description, actions }: { title: string; description?: string; actions?: Snippet } = $props();
</script>

<header>
  <div>
    <h1>{title}</h1>
    {#if description}<p>{description}</p>{/if}
  </div>
  {#if actions}<div class="actions">{@render actions()}</div>{/if}
</header>

<style>
  header { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  p { margin-top: 3px; color: var(--muted); max-width: 72ch; }
  .actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
</style>
