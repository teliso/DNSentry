<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '../components/Card.svelte';
  import { api } from '../lib/api';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { LocalSummary } from '../lib/types';

  let { onclose }: { onclose: () => void } = $props();

  let original = $state<string | null>(null);
  let text = $state('');
  let summary = $state<LocalSummary | null>(null);
  const dirty = $derived(original !== null && text !== original);
  const lines = $derived(text === '' ? 0 : text.replace(/\n$/, '').split('\n').length);

  onMount(async () => {
    try {
      original = await api.localRules();
      text = original;
    } catch (cause) {
      toasts.error(cause instanceof Error ? cause.message : '读取规则文件失败');
    }
  });

  async function save() {
    const result = await store.saveLocalRules(text);
    if (!result) return;
    summary = result;
    original = text.endsWith('\n') || text === '' ? text : `${text}\n`;
    text = original;
    if (result.ignored > 0) toasts.info(`已保存 ${result.rules} 条规则，${result.ignored} 行无法识别`);
    else toasts.success(`已保存 ${result.rules} 条规则`);
  }

  function close() {
    if (!dirty || confirm('放弃未保存的修改？')) onclose();
  }

  function onkeydown(event: KeyboardEvent) {
    if ((event.ctrlKey || event.metaKey) && event.key === 's') {
      event.preventDefault();
      if (dirty && !store.busy) void save();
    }
  }
</script>

<Card title="编辑 rules.txt" description="每行一条：example.com、||example.com^、@@||example.com^ 或 0.0.0.0 example.com；以 # 或 ! 开头为注释。保存后立即生效。">
  {#snippet actions()}
    <span class="muted tabular">{lines} 行</span>
  {/snippet}
  {#if original === null}
    <p class="muted">正在读取…</p>
  {:else}
    <textarea
      class="mono"
      rows="22"
      spellcheck="false"
      autocapitalize="off"
      aria-label="rules.txt 内容"
      bind:value={text}
      {onkeydown}
    ></textarea>
    {#if summary && summary.ignored > 0}
      <p class="warn">
        以下行无法识别，已忽略（修饰符、通配符、正则和非拦截 hosts 条目不受支持）：第 {summary.ignored_lines.join('、')} 行{summary.ignored > summary.ignored_lines.length ? ' 等' : ''}。
      </p>
    {/if}
    <div class="actions">
      <button class="btn" type="button" onclick={close}>{dirty ? '取消' : '关闭'}</button>
      <button class="btn primary" type="button" disabled={!dirty || store.busy} onclick={save}>保存（Ctrl+S）</button>
    </div>
  {/if}
</Card>

<style>
  textarea { font-size: 13px; line-height: 1.6; min-height: 320px; }
  .warn { margin-top: 10px; color: var(--warn); font-size: 13px; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
</style>
