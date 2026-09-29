<script lang="ts">
  import { flip } from 'svelte/animate';
  import { fly } from 'svelte/transition';
  import { toasts } from '../lib/toast.svelte';
  import Icon from './Icon.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts.items as toast (toast.id)}
    <div class="toast {toast.tone}" role={toast.tone === 'error' ? 'alert' : 'status'} animate:flip={{ duration: 150 }} transition:fly={{ y: 12, duration: 160 }}>
      <Icon name={toast.tone === 'error' ? 'alert' : 'check'} />
      <span>{toast.text}</span>
      <button type="button" aria-label="关闭提示" onclick={() => toasts.dismiss(toast.id)}><Icon name="x" size={14} /></button>
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed; z-index: 200; right: 20px; bottom: 20px;
    display: flex; flex-direction: column; gap: 8px; width: min(380px, calc(100vw - 32px));
  }
  .toast {
    display: flex; align-items: flex-start; gap: 10px; padding: 11px 12px;
    background: var(--surface); border: 1px solid var(--line); border-left-width: 3px;
    border-radius: var(--radius-sm); box-shadow: var(--shadow-pop);
  }
  .toast :global(svg:first-child) { margin-top: 3px; }
  .toast.success { border-left-color: var(--ok); }
  .toast.success :global(svg:first-child) { color: var(--ok); }
  .toast.error { border-left-color: var(--danger); }
  .toast.error :global(svg:first-child) { color: var(--danger); }
  .toast.info { border-left-color: var(--accent); }
  .toast.info :global(svg:first-child) { color: var(--accent); }
  span { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  button { flex: none; border: 0; background: transparent; color: var(--muted); cursor: pointer; padding: 4px; border-radius: 4px; }
  button:hover { color: var(--ink); background: var(--surface-2); }
  @media (max-width: 640px) { .toasts { right: 16px; bottom: 76px; } }
</style>
