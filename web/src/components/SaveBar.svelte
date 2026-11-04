<script lang="ts">
  import Icon from './Icon.svelte';
  import { diffConfig } from '../lib/configDiff';
  import { store } from '../lib/store.svelte';

  let open = $state(false);
  const changes = $derived(store.dirty && store.saved && store.draft ? diffConfig(store.saved, store.draft) : []);

  $effect(() => {
    if (!store.dirty) open = false;
  });
</script>

{#if store.dirty}
  <div class="savebar" role="region" aria-label="未保存的更改">
    {#if open}
      <div class="changes" role="list">
        {#each changes as change (change.path)}
          <div class="change" role="listitem">
            <strong>{change.label}</strong>
            {#if change.added !== undefined || change.removed !== undefined}
              <ul>
                {#each change.removed ?? [] as item (item)}<li class="del"><span>−</span>{item}</li>{/each}
                {#each change.added ?? [] as item (item)}<li class="add"><span>+</span>{item}</li>{/each}
              </ul>
            {:else}
              <span class="values"><del>{change.before}</del><Icon name="chevron" size={14} /><ins>{change.after}</ins></span>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
    <div class="bar">
      <button class="summary" type="button" aria-expanded={open} onclick={() => (open = !open)}>
        <span class="pulse"></span>
        有未保存的更改（{changes.length} 项）
        <span class="toggle">{open ? '收起' : '查看更改'}<span class:flip={open}><Icon name="chevron-down" size={14} /></span></span>
      </button>
      <div class="buttons">
        <button class="btn" type="button" disabled={store.busy} onclick={() => store.discardDraft()}>放弃</button>
        <button class="btn primary" type="button" disabled={store.busy} onclick={() => store.saveConfig()}>保存配置</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* Fixed to the bottom of the window, whatever the length of the page. */
  .savebar {
    position: fixed; z-index: 60; left: 50%; bottom: 16px; transform: translateX(-50%);
    width: min(760px, calc(100% - 2 * var(--gutter)));
    background: var(--surface); border: 1px solid var(--line-strong); border-radius: var(--radius); box-shadow: var(--shadow-pop);
  }
  .bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px 10px 6px; }
  .summary {
    display: flex; align-items: center; gap: 8px; min-width: 0; padding: 6px 12px; border: 0; border-radius: var(--radius-sm);
    background: none; font-weight: 500; text-align: left; cursor: pointer;
  }
  .summary:hover { background: var(--surface-2); }
  .toggle { display: inline-flex; align-items: center; gap: 2px; color: var(--accent); font-size: 12px; font-weight: 500; white-space: nowrap; }
  .toggle .flip { display: inline-flex; transform: rotate(180deg); }
  .pulse { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--series-blocked); }
  .buttons { display: flex; gap: 8px; flex: none; }
  .changes { max-height: min(50vh, 360px); overflow: auto; padding: 8px 8px 0; border-bottom: 1px solid var(--line); }
  .change { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; padding: 7px 10px; border-radius: var(--radius-sm); }
  .change:nth-child(odd) { background: var(--surface-2); }
  .change strong { flex: 0 0 170px; font-weight: 600; }
  .values { display: inline-flex; align-items: center; gap: 6px; min-width: 0; flex: 1; flex-wrap: wrap; font-size: 13px; }
  .values del { color: var(--muted); text-decoration-color: var(--danger); }
  .values ins { color: var(--ink); text-decoration: none; font-weight: 500; }
  ul { list-style: none; margin: 0; padding: 0; flex: 1; min-width: 0; font-size: 13px; font-family: var(--font-mono); }
  li { display: flex; gap: 6px; overflow-wrap: anywhere; }
  li span { flex: none; width: 12px; font-weight: 700; }
  li.add span { color: var(--ok); }
  li.del span { color: var(--danger); }
  li.del { color: var(--muted); }
  @media (max-width: 900px) {
    /* above the bottom navigation bar */
    .savebar { bottom: calc(68px + env(safe-area-inset-bottom)); }
    .change strong { flex-basis: 100%; }
    .summary { font-size: 13px; padding: 6px 8px; }
  }
</style>
