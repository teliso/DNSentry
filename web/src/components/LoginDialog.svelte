<script lang="ts">
  import Field from './Field.svelte';
  import Modal from './Modal.svelte';
  import { store } from '../lib/store.svelte';

  let username = $state(store.auth?.username ?? 'admin');
  let password = $state('');
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !username.trim() || !password) return;
    busy = true;
    const ok = await store.signIn(username, password);
    busy = false;
    if (!ok) password = '';
  }
</script>

<Modal title="登录 DNSentry" dismissible={false}>
  <form id="login-form" onsubmit={submit}>
    <Field label="用户名"><input bind:value={username} autocomplete="username" autocapitalize="off" spellcheck="false" /></Field>
    <Field label="密码"><input type="password" bind:value={password} autocomplete="current-password" /></Field>
  </form>
  {#snippet footer()}
    <button class="btn primary" type="submit" form="login-form" disabled={busy || !username.trim() || !password}>登录</button>
  {/snippet}
</Modal>

<style>
  form { display: flex; flex-direction: column; gap: 14px; }
</style>
