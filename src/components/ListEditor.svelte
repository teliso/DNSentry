<script lang="ts">
  export let label = '';
  export let hint = '';
  export let placeholder = '';
  export let values: string[] = [];


  export let disabled = false;
  export let code = false;
  export let maxItems = 0;

  let text = '';
  let editing = false;

  function parseLines(value: string) {
    const parsed = value.split('\n').map((item) => item.trim()).filter(Boolean);
    return maxItems > 0 ? parsed.slice(0, maxItems) : parsed;
  }

  function update(event: Event) {
    const target = event.currentTarget as HTMLTextAreaElement;
    editing = true;
    const nextValues = parseLines(target.value);
    if (maxItems > 0 && nextValues.length >= maxItems && target.value.split('\n').filter((item) => item.trim()).length > maxItems) {
      text = nextValues.join('\n');
    } else {
      text = target.value;
    }
    values = nextValues;
  }

  function finishEditing() {
    editing = false;
    text = values.join('\n');
  }

  $: if (!editing) text = values.join('\n');
</script>

<div class:code-editor={code} class:disabled-editor={disabled} class="list-editor">
  {#if label || hint}
    <div class="list-editor-heading">
      <div>
        {#if label}<span class="field-label">{label}</span>{/if}
        {#if hint}<small>{hint}</small>{/if}
      </div>
      <span class="list-count">{values.length}{maxItems > 0 ? ` / ${maxItems}` : ''}</span>
    </div>
  {/if}
  <textarea
    value={text}
    placeholder={placeholder}
    disabled={disabled}
    aria-label={label || '多行配置'}
    spellcheck="false"
    oninput={update}
    onblur={finishEditing}
  ></textarea>
  <small class="list-editor-help">每行一项 · 粘贴多行内容即可批量配置</small>
</div>
