<script lang="ts">
  import type { Snippet } from 'svelte';

  let { label, hint, children }: { label: string; hint?: string; children: Snippet } = $props();
</script>

<label class="field">
  <span class="label">{label}</span>
  {@render children()}
  {#if hint}<small class="hint">{hint}</small>{/if}
</label>

<style>
  .field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .label { font-weight: 500; font-size: 13px; }
  .hint { color: var(--muted); }
</style>
