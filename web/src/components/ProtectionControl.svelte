<script lang="ts">
  import Icon from './Icon.svelte';
  import { store } from '../lib/store.svelte';

  const DURATIONS = [
    { minutes: 5, label: '5 分钟' },
    { minutes: 30, label: '30 分钟' },
    { minutes: 60, label: '1 小时' },
    { minutes: 1440, label: '24 小时' },
    { minutes: 0, label: '直到手动恢复' }
  ];

  const paused = $derived(store.status?.protection?.enabled === false);
  let menu: HTMLDetailsElement | undefined = $state();

  function pause(minutes: number) {
    if (menu) menu.open = false;
    void store.setProtection(false, minutes);
  }
</script>

{#if paused}
  <button class="btn primary" type="button" disabled={store.busy} onclick={() => store.setProtection(true)}><Icon name="play" />恢复过滤</button>
{:else}
  <details class="menu" bind:this={menu}>
    <summary class="btn" aria-haspopup="menu"><Icon name="pause" />暂停过滤<Icon name="chevron-down" size={14} /></summary>
    <ul role="menu">
      {#each DURATIONS as item (item.minutes)}
        <li role="none"><button type="button" role="menuitem" disabled={store.busy} onclick={() => pause(item.minutes)}>{item.label}</button></li>
      {/each}
    </ul>
  </details>
{/if}

<style>
  .menu { position: relative; }
  summary { list-style: none; user-select: none; }
  summary::-webkit-details-marker { display: none; }
  ul {
    position: absolute; right: 0; top: calc(100% + 6px); z-index: 40; min-width: 168px; margin: 0; padding: 4px; list-style: none;
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius-sm); box-shadow: var(--shadow-pop);
  }
  li button { width: 100%; padding: 7px 10px; border: 0; border-radius: 6px; background: none; text-align: left; cursor: pointer; }
  li button:hover:not(:disabled) { background: var(--surface-2); }
  li button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
