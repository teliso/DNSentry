<script lang="ts">
  import Icon from './Icon.svelte';
  import { computeAlerts } from '../lib/alerts';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';

  const alerts = $derived(computeAlerts(store.status));
  const paused = $derived(store.status && store.status.protection?.enabled === false ? store.status.protection : null);
  const here = $derived(`${router.current}/${router.tab}`);

  function resumeTime(iso?: string) {
    return iso ? new Date(iso).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : '';
  }
</script>

{#if paused || alerts.length > 0}
  <div class="alerts" role="region" aria-label="需要注意的问题">
    {#if paused}
      <div class="alert warn" role="status">
        <Icon name="pause" />
        <span>过滤已暂停：广告和恶意域名目前不会被拦截{paused.resume_at ? `，将在 ${resumeTime(paused.resume_at)} 自动恢复` : '，需要手动恢复'}。</span>
        <button class="btn sm" type="button" disabled={store.busy} onclick={() => store.setProtection(true)}>立即恢复</button>
      </div>
    {/if}
    {#each alerts as alert (alert.id)}
      <div class="alert {alert.tone}" role={alert.tone === 'danger' ? 'alert' : 'status'}>
        <Icon name="alert" />
        <span>{alert.text}</span>
        {#if alert.route && !`${alert.route}/`.startsWith(`${here}/`)}
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
