<script lang="ts">
  import { ask } from '../lib/i18n/index.svelte';
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import { store } from '../lib/store.svelte';

  const configured = $derived(store.auth?.configured ?? false);
  let username = $state(store.auth?.username ?? 'admin');
  let password = $state('');
  let repeat = $state('');
  let current = $state('');

  const mismatch = $derived(repeat !== '' && repeat !== password);
  const tooShort = $derived(password !== '' && [...password].length < 8);
  const canSave = $derived(!store.busy && username.trim() !== '' && password !== '' && !tooShort && repeat === password && (!configured || current !== ''));

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!canSave) return;
    if (await store.changeLogin({ username: username.trim(), password, current })) {
      password = repeat = current = '';
    }
  }

  async function remove() {
    if (current === '') return;
    if (ask('关闭控制台登录后，只有本机（或持有 API Token 的人）可以访问控制台。确定关闭？') && (await store.changeLogin({ remove: true, current }))) current = '';
  }
</script>

<Card title="控制台登录" description="设置用户名和密码后，打开控制台需要先登录，包括在本机访问时。密码用 bcrypt 加密保存在配置文件同目录的 auth.json 中。">
  {#snippet actions()}
    <span class="badge" class:ok={configured}>{configured ? '已启用' : '未启用'}</span>
  {/snippet}

  <form class="stack" onsubmit={save}>
    {#if !configured}
      <p class="note">目前只有本机可以直接访问控制台。设置密码后，可以放心让局域网内的其他设备访问（还需要把控制台监听地址改成非回环地址，并设置环境变量 <code>DNSENTRY_ALLOW_PUBLIC_WEB=1</code>）。</p>
    {/if}
    <div class="form-grid two">
      <Field label="用户名"><input bind:value={username} autocomplete="username" autocapitalize="off" spellcheck="false" /></Field>
      {#if configured}
        <Field label="当前密码" hint="修改或关闭登录前需要先确认"><input type="password" bind:value={current} autocomplete="current-password" /></Field>
      {/if}
      <Field label={configured ? '新密码' : '密码'} hint={tooShort ? '至少 8 个字符' : '至少 8 个字符，不超过 72 字节'}>
        <input type="password" bind:value={password} autocomplete="new-password" aria-invalid={tooShort} />
      </Field>
      <Field label="再输一次" hint={mismatch ? '两次输入不一致' : ''}>
        <input type="password" bind:value={repeat} autocomplete="new-password" aria-invalid={mismatch} />
      </Field>
    </div>
    <div class="actions">
      <button class="btn primary" type="submit" disabled={!canSave}>{configured ? '修改密码' : '启用登录'}</button>
      {#if configured}
        <button class="btn danger" type="button" disabled={store.busy || current === ''} onclick={remove}>关闭登录</button>
      {/if}
    </div>
    {#if configured}
      <p class="muted small">修改密码会让其他浏览器的登录失效；重启服务也会让所有登录失效。如果同时设置了 <code>DNSENTRY_API_TOKEN</code>，脚本仍然可以用令牌访问 API。忘记密码时，删除 <code>auth.json</code> 并重启即可。</p>
    {/if}
  </form>
</Card>

<style>
  .note { padding: 9px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); color: var(--ink-2); }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .small { font-size: 12px; }
  input[aria-invalid='true'] { border-color: var(--danger); }
</style>
