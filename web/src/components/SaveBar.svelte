<script lang="ts">
  import { store } from '../lib/store.svelte';
</script>

{#if store.dirty}
  <div class="savebar" role="region" aria-label="未保存的更改">
    <span><span class="pulse"></span>有未保存的更改</span>
    <div>
      <button class="btn" type="button" disabled={store.busy} onclick={() => store.discardDraft()}>放弃</button>
      <button class="btn primary" type="button" disabled={store.busy} onclick={() => store.saveConfig()}>保存配置</button>
    </div>
  </div>
{/if}

<style>
  .savebar {
    position: sticky; bottom: 16px; z-index: 30;
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 10px 12px 10px 18px;
    background: var(--surface); border: 1px solid var(--line-strong); border-radius: var(--radius);
    box-shadow: var(--shadow-pop);
  }
  .savebar > span { display: flex; align-items: center; gap: 8px; font-weight: 500; }
  .pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--series-blocked); }
  div { display: flex; gap: 8px; }
  @media (max-width: 860px) { .savebar { bottom: 12px; } }
</style>
