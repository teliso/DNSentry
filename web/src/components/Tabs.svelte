<script lang="ts">
  import { router, type Target } from '../lib/router.svelte';

  /** Sub-navigation of a page; the active tab lives in the address bar (#page/tab). */
  let { page, tabs }: { page: string; tabs: { id: string; label: string; badge?: string }[] } = $props();
</script>

<nav class="tabs" aria-label="分页">
  {#each tabs as tab (tab.id)}
    <a href={router.href(`${page}/${tab.id}` as Target)} class:active={router.tab === tab.id} aria-current={router.tab === tab.id ? 'page' : undefined}>
      {tab.label}{#if tab.badge}<span class="badge">{tab.badge}</span>{/if}
    </a>
  {/each}
</nav>

<style>
  .tabs {
    position: sticky; top: var(--topbar-height); z-index: 20;
    display: flex; gap: 2px; overflow-x: auto; scrollbar-width: none;
    margin: 0 calc(-1 * var(--gutter)); padding: 0 var(--gutter);
    background: var(--bg); border-bottom: 1px solid var(--line);
  }
  .tabs::-webkit-scrollbar { display: none; }
  a {
    position: relative; flex: none; display: flex; align-items: center; gap: 6px;
    padding: 11px 14px; color: var(--ink-2); font-weight: 500; text-decoration: none; white-space: nowrap;
  }
  a:hover { color: var(--ink); }
  a.active { color: var(--accent); }
  a.active::after { content: ''; position: absolute; left: 10px; right: 10px; bottom: -1px; height: 2px; border-radius: 2px; background: var(--accent); }
  a:focus-visible { box-shadow: inset var(--focus); border-radius: 6px; }
</style>
