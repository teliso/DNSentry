<script lang="ts">
  import Card from '../components/Card.svelte';
  import Icon from '../components/Icon.svelte';
  import Switch from '../components/Switch.svelte';
  import { api } from '../lib/api';
  import { toasts } from '../lib/toast.svelte';
  import type { Config, NotificationEvent, Webhook } from '../lib/types';

  let { config }: { config: Config } = $props();
  const hooks = $derived(config.notifications.webhooks);
  let testing = $state(-1);

  const EVENTS: { id: NotificationEvent; label: string; text: string }[] = [
    { id: 'upstream', label: '上游故障', text: '所有默认上游、或某条域名分流的上游全部没有响应（以及恢复时）' },
    { id: 'rule_source', label: '规则源更新失败', text: '规则源超过一天（或两个更新周期）没有更新成功（以及恢复时）' }
  ];

  function add() {
    config.notifications.webhooks = [...hooks, { name: '', url: '', format: 'json', enabled: true }];
  }

  function remove(index: number) {
    config.notifications.webhooks = hooks.filter((_, current) => current !== index);
  }

  /** An empty selection means "everything"; the checkboxes show that as all ticked. */
  const selected = $derived(new Set(config.notifications.events.length === 0 ? EVENTS.map((event) => event.id) : config.notifications.events));

  function toggle(id: NotificationEvent, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    // All ticked is stored as the empty list, so newly added kinds of events are included automatically.
    config.notifications.events = next.size === EVENTS.length || next.size === 0 ? [] : ([...next] as NotificationEvent[]);
  }

  async function test(hook: Webhook, index: number) {
    testing = index;
    try {
      await api.testWebhook({ url: hook.url.trim(), format: hook.format, name: hook.name });
      toasts.success('测试消息已发送，请到接收端确认');
    } catch (cause) {
      toasts.error(cause instanceof Error ? cause.message : '发送失败');
    } finally {
      testing = -1;
    }
  }
</script>

<Card title="通知" description="上游或规则源出问题时主动发消息给你，不用一直开着控制台。问题持续约 1 分钟才会通知（避免瞬时抖动），恢复时再通知一次。">
  <div class="stack">
    {#if hooks.length === 0}
      <p class="muted">还没有配置接收地址。添加一个 Webhook 后，这里会列出它。</p>
    {/if}

    {#each hooks as hook, index (index)}
      <div class="hook" class:off={!hook.enabled}>
        <div class="row">
          <input class="name" bind:value={hook.name} placeholder="名称（可选，如 手机）" maxlength="64" aria-label="名称" />
          <select bind:value={hook.format} aria-label="消息格式">
            <option value="json">JSON（Slack / Discord / Gotify 等）</option>
            <option value="plain">纯文本（ntfy）</option>
          </select>
          <Switch bind:checked={hook.enabled} label="启用" />
        </div>
        <div class="row">
          <input class="mono url" type="url" bind:value={hook.url} placeholder="https://ntfy.sh/你的主题  或  https://discord.com/api/webhooks/…" spellcheck="false" aria-label="Webhook 地址" />
          <button class="btn sm" type="button" disabled={testing !== -1 || !hook.url.trim()} onclick={() => test(hook, index)}>{testing === index ? '发送中…' : '测试'}</button>
          <button class="btn sm danger icon" type="button" aria-label="删除" onclick={() => remove(index)}><Icon name="trash" /></button>
        </div>
      </div>
    {/each}

    <div><button class="btn" type="button" disabled={hooks.length >= 8} onclick={add}><Icon name="plus" />添加 Webhook</button></div>

    <fieldset>
      <legend>通知哪些事件</legend>
      {#each EVENTS as event (event.id)}
        <label class="event">
          <input type="checkbox" checked={selected.has(event.id)} onchange={(change) => toggle(event.id, change.currentTarget.checked)} />
          <span><strong>{event.label}</strong><small>{event.text}</small></span>
        </label>
      {/each}
    </fieldset>

    <p class="muted small">
      JSON 格式同时带有 <code>title</code> / <code>message</code>（Gotify）、<code>text</code>（Slack、Mattermost）、<code>content</code>（Discord）字段；纯文本格式把消息正文作为请求体、标题放在 <code>Title</code> 头里（ntfy）。Webhook 地址里往往包含密钥，请当作密码保管；服务器会主动访问你填的地址，不会跟随重定向。
    </p>
  </div>
</Card>

<style>
  .hook { display: flex; flex-direction: column; gap: 8px; padding: 12px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .hook.off { opacity: 0.65; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .name { flex: 1 1 180px; }
  .row select { flex: 1 1 240px; width: auto; }
  .url { flex: 1 1 280px; }
  fieldset { margin: 0; padding: 12px 14px; border: 1px solid var(--line); border-radius: var(--radius-sm); display: flex; flex-direction: column; gap: 10px; }
  legend { padding: 0 6px; color: var(--muted); font-size: 12px; }
  .event { display: flex; gap: 10px; align-items: flex-start; cursor: pointer; }
  .event input { margin-top: 4px; }
  .event span { display: flex; flex-direction: column; }
  small { color: var(--muted); }
  .small { font-size: 12px; }
</style>
