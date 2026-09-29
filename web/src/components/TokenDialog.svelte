<script lang="ts">
  import Field from './Field.svelte';
  import Modal from './Modal.svelte';
  import { store } from '../lib/store.svelte';

  let token = $state('');

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (token.trim()) void store.submitToken(token);
  }
</script>

<Modal title="需要 API Token" dismissible={false}>
  <form id="token-form" onsubmit={submit}>
    <p class="muted">此实例启用了访问令牌（环境变量 <code>DNSENTRY_API_TOKEN</code>）。输入令牌后会保存在当前浏览器的 localStorage 中。</p>
    <Field label="API Token">
      <input type="password" bind:value={token} autocomplete="off" placeholder="粘贴令牌" />
    </Field>
  </form>
  {#snippet footer()}
    <button class="btn primary" type="submit" form="token-form" disabled={!token.trim()}>继续</button>
  {/snippet}
</Modal>

<style>
  form { display: flex; flex-direction: column; gap: 14px; }
</style>
