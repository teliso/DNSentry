<script lang="ts">
  let {
    label,
    hint,
    placeholder = '',
    values = $bindable<string[]>([]),
    disabled = false,
    code = false,
    maxItems = 0,
    rows = 4
  }: {
    label: string;
    hint?: string;
    placeholder?: string;
    values?: string[];
    disabled?: boolean;
    code?: boolean;
    maxItems?: number;
    rows?: number;
  } = $props();

  let text = $state('');
  let focused = false;
  let overLimit = $state(false);

  // Mirror external changes (load, discard, restore) unless the user is typing.
  $effect(() => {
    const joined = (values ?? []).join('\n');
    if (!focused) text = joined;
  });

  function parse(raw: string): string[] {
    return raw.split('\n').map((line) => line.trim()).filter(Boolean);
  }

  function oninput(event: Event & { currentTarget: HTMLTextAreaElement }) {
    text = event.currentTarget.value;
    const items = parse(text);
    overLimit = maxItems > 0 && items.length > maxItems;
    values = maxItems > 0 ? items.slice(0, maxItems) : items;
  }

  function onblur() {
    focused = false;
    text = (values ?? []).join('\n');
    overLimit = false;
  }
</script>

<div class="list-editor" class:code>
  <div class="top">
    <span class="label">{label}</span>
    <span class="count tabular" class:over={overLimit}>{values?.length ?? 0}{maxItems > 0 ? ` / ${maxItems}` : ''}</span>
  </div>
  <textarea
    {rows}
    {placeholder}
    {disabled}
    value={text}
    aria-label={label}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
    {oninput}
    onfocus={() => (focused = true)}
    {onblur}
  ></textarea>
  <small class="hint">{hint ? `${hint} · ` : ''}每行一项，可粘贴多行</small>
</div>

<style>
  .list-editor { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .top { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .label { font-weight: 500; font-size: 13px; }
  .count { color: var(--muted); font-size: 12px; }
  .count.over { color: var(--danger); }
  .code textarea { font-family: var(--font-mono); font-size: 13px; }
  .hint { color: var(--muted); }
</style>
