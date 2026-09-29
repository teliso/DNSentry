<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    title,
    onclose,
    dismissible = true,
    children,
    footer
  }: { title: string; onclose?: () => void; dismissible?: boolean; children: Snippet; footer?: Snippet } = $props();

  let dialog: HTMLDivElement | undefined = $state();
  const titleId = `modal-${Math.random().toString(36).slice(2)}`;

  $effect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog?.querySelector<HTMLElement>('input, button:not(.close), textarea, select')?.focus();
    return () => previous?.focus?.();
  });

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && dismissible) onclose?.();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation" onpointerdown={(event) => dismissible && event.target === event.currentTarget && onclose?.()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} bind:this={dialog}>
    <header>
      <h2 id={titleId}>{title}</h2>
      {#if dismissible}
        <button class="btn ghost sm icon close" type="button" aria-label="关闭" onclick={() => onclose?.()}><Icon name="x" /></button>
      {/if}
    </header>
    <div class="content">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed; inset: 0; z-index: 100; display: grid; place-items: center; padding: 16px;
    background: rgb(10 14 24 / 0.5); backdrop-filter: blur(2px);
  }
  .dialog {
    width: min(560px, 100%); max-height: calc(100dvh - 32px); display: flex; flex-direction: column;
    background: var(--surface); border: 1px solid var(--line); border-radius: 12px; box-shadow: var(--shadow-pop);
  }
  header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 16px 20px 0; }
  h2 { font-size: 16px; }
  .content { padding: 14px 20px; overflow: auto; }
  footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 20px 16px; border-top: 1px solid var(--line); }
</style>
