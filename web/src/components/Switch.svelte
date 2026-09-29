<script lang="ts">
  let {
    checked = $bindable(false),
    label,
    description,
    disabled = false,
    onchange
  }: { checked?: boolean; label: string; description?: string; disabled?: boolean; onchange?: (checked: boolean) => void } = $props();
</script>

<label class="switch" class:disabled>
  <input type="checkbox" role="switch" bind:checked {disabled} onchange={() => onchange?.(checked)} />
  <span class="track" aria-hidden="true"><span class="thumb"></span></span>
  <span class="text">
    <span class="label">{label}</span>
    {#if description}<small>{description}</small>{/if}
  </span>
</label>

<style>
  .switch { display: flex; align-items: flex-start; gap: 12px; cursor: pointer; }
  .switch.disabled { cursor: not-allowed; opacity: 0.55; }
  input { position: absolute; opacity: 0; pointer-events: none; }
  .track {
    flex: none; position: relative; width: 36px; height: 20px; margin-top: 1px;
    border-radius: 999px; background: var(--line-strong); transition: background 0.15s;
  }
  .thumb {
    position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
    border-radius: 50%; background: #fff; box-shadow: 0 1px 2px rgb(0 0 0 / 0.3);
    transition: transform 0.15s;
  }
  input:checked + .track { background: var(--accent); }
  input:checked + .track .thumb { transform: translateX(16px); }
  input:focus-visible + .track { box-shadow: var(--focus); }
  .text { display: flex; flex-direction: column; min-width: 0; }
  .label { font-weight: 500; }
  small { color: var(--muted); }
</style>
