<script lang="ts">
  import { untrack } from 'svelte';
  import Card from './Card.svelte';
  import Icon from './Icon.svelte';
  import { api } from '../lib/api';
  import { ruleText, sourceName } from '../lib/rules';
  import { store } from '../lib/store.svelte';
  import type { Rule, RuleCheck } from '../lib/types';

  let domain = $state('');
  let result = $state<RuleCheck | null>(null);
  let error = $state('');
  let checking = $state(false);

  async function check(event?: SubmitEvent) {
    event?.preventDefault();
    if (!domain.trim()) return;
    checking = true;
    error = '';
    try {
      result = await api.checkRule(domain.trim());
    } catch (cause) {
      result = null;
      error = cause instanceof Error ? cause.message : '检测失败';
    } finally {
      checking = false;
    }
  }

  // Re-run the last check after rules change so the verdict stays current.
  let seenVersion = store.rulesVersion;
  $effect(() => {
    const version = store.rulesVersion;
    if (version === seenVersion) return;
    seenVersion = version;
    untrack(() => {
      if (result) void check();
    });
  });

  const same = (left: Rule, right: Rule | undefined) =>
    !!right && left.domain === right.domain && left.action === right.action && (left.source ?? '') === (right.source ?? '');

  /** Local allow rules win over everything, so undo them by deleting; otherwise add a precise rule. */
  const removable = $derived(result?.rule && !result.rule.source && result.rule.action === 'allow' ? result.rule : null);

  async function fix() {
    if (!result) return;
    if (removable) await store.removeRule(removable);
    else await store.addRule(result.domain, result.rule?.action === 'block' ? 'allow' : 'block');
  }
</script>

<Card title="规则检测" description="查看某个域名会被哪条规则拦截或放行。">
  <form class="check" onsubmit={check}>
    <input aria-label="要检测的域名" placeholder="tracker.example.com" bind:value={domain} autocapitalize="off" spellcheck="false" />
    <button class="btn" type="submit" disabled={checking || !domain.trim()}><Icon name="search" />检测</button>
  </form>

  {#if error}
    <p class="error">{error}</p>
  {:else if result}
    <div class="verdict" aria-live="polite">
      {#if result.rule}
        <span class="badge" class:danger={result.rule.action === 'block'} class:ok={result.rule.action === 'allow'}>
          {result.rule.action === 'block' ? '将被拦截' : '已放行'}
        </span>
        <span class="mono">{ruleText(result.rule)}</span>
        <span class="muted">· {sourceName(result.rule.source, store.sources)}</span>
      {:else}
        <span class="badge">无匹配规则</span>
        <span class="muted">{result.domain} 会正常解析</span>
      {/if}
      <button class="btn sm" type="button" disabled={store.busy} onclick={fix}>
        {removable ? '删除这条放行规则' : result.rule?.action === 'block' ? '放行此域名' : '拦截此域名'}
      </button>
    </div>
    {#if result.candidates.length > 1}
      <ul class="candidates">
        {#each result.candidates as rule, index (index)}
          <li class:winner={same(rule, result.rule)}>
            <span class="mono">{ruleText(rule)}</span>
            <span class="muted">{sourceName(rule.source, store.sources)}</span>
          </li>
        {/each}
      </ul>
      <p class="muted note">共 {result.candidates.length} 条规则匹配该域名或其上级域名，高亮的一条生效。</p>
    {/if}
  {/if}
</Card>

<style>
  .check { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; }
  .verdict { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .verdict .btn { margin-left: auto; }
  .mono { font-size: 13px; word-break: break-all; }
  .error { margin-top: 12px; color: var(--danger); }
  .candidates { list-style: none; margin: 12px 0 0; padding: 0; border: 1px solid var(--line); border-radius: var(--radius-sm); max-height: 180px; overflow: auto; }
  .candidates li { display: flex; justify-content: space-between; gap: 12px; padding: 6px 10px; border-top: 1px solid var(--line); font-size: 13px; }
  .candidates li:first-child { border-top: 0; }
  .candidates li.winner { background: var(--accent-soft); }
  .note { margin-top: 6px; font-size: 12px; }
</style>
