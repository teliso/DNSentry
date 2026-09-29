<script lang="ts">
  import Icon from './Icon.svelte';
  import { computeAlerts } from '../lib/alerts';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';

  const alerts = $derived(computeAlerts(store.status));
</script>

{#if alerts.length > 0}
  <div class="alerts" role="region" aria-label="需要注意的问题">
    {#each alerts as alert (alert.id)}
      <div class="alert {alert.tone}" role={alert.tone === 'danger' ? 'alert' : 'status'}>
        <Icon name="alert" />
        <span>{alert.text}</span>
        {#if alert.route && router.current !== alert.route}
          <button class="btn sm" type="button" onclick={() => router.go(alert.route!)}>{alert.action}</button>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .alerts { display: flex; flex-direction: column; gap: 8px; }
  .alert { display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px; border-radius: var(--radius-sm); color: var(--ink-2); }
  .alert :global(svg) { margin-top: 3px; flex: none; }
  .alert span { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .alert.warn { background: var(--warn-soft); }
  .alert.warn :global(svg) { color: var(--warn); }
  .alert.danger { background: var(--danger-soft); }
  .alert.danger :global(svg) { color: var(--danger); }
  .alert .btn { flex: none; }
</style>
