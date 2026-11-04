<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import { toasts } from '../lib/toast.svelte';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
  const running = $derived(store.status?.web_tls);
  const custom = $derived(config.web_tls.certificate.trim() !== '' || config.web_tls.private_key.trim() !== '');

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toasts.success('已复制');
    } catch {
      toasts.error('无法访问剪贴板，请手动复制');
    }
  }
</script>

<Card title="控制台 HTTPS" description="用 HTTPS 提供控制台，登录密码和会话 Cookie 不再明文传输。适合需要从其他设备访问控制台的情况。">
  {#snippet actions()}
    <span class="badge" class:ok={running?.enabled}>{running?.enabled ? '正在使用 HTTPS' : '正在使用 HTTP'}</span>
    <span class="badge warn">重启后生效</span>
  {/snippet}

  <div class="stack">
    <Switch bind:checked={config.web_tls.enabled} label="启用 HTTPS" description="启用后控制台地址变成 https://…；原来的 http:// 地址将无法访问。" />

    {#if config.web_tls.enabled}
      <div class="form-grid two">
        <Field label="证书文件" hint="PEM 格式，可包含中间证书链；留空则自动生成自签名证书">
          <input class="mono" bind:value={config.web_tls.certificate} placeholder="/etc/ssl/dnsentry/fullchain.pem" spellcheck="false" />
        </Field>
        <Field label="私钥文件" hint="与证书配套的 PEM 私钥">
          <input class="mono" bind:value={config.web_tls.private_key} placeholder="/etc/ssl/dnsentry/privkey.pem" spellcheck="false" />
        </Field>
      </div>
      {#if !custom}
        <p class="note">将使用<strong>自签名证书</strong>（保存在配置文件同目录的 <code>web-tls.crt</code> / <code>web-tls.key</code>，包含本机主机名和当前网卡地址）。浏览器会提示“不安全”：请核对下面的指纹后选择继续。想要不再提示，请填写自己的证书，例如用 mkcert 生成并把根证书装到设备上，或用 Let's Encrypt。</p>
      {:else}
        <p class="muted small">证书文件更新后（如续期）会自动生效，无需重启。</p>
      {/if}
    {/if}

    {#if running?.enabled && running.fingerprint}
      <dl class="info">
        <div><dt>当前证书</dt><dd>{running.mode === 'self-signed' ? '自签名' : '自定义'}{running.not_after ? `，有效期至 ${new Date(running.not_after).toLocaleDateString('zh-CN')}` : ''}</dd></div>
        <div>
          <dt>SHA-256 指纹</dt>
          <dd class="mono fingerprint">{running.fingerprint} <button class="btn ghost sm" type="button" onclick={() => copy(running.fingerprint ?? '')}>复制</button></dd>
        </div>
      </dl>
    {/if}
  </div>
</Card>

<style>
  .note { padding: 9px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); color: var(--ink-2); }
  .small { font-size: 12px; }
  .info { display: grid; gap: 10px; margin: 0; }
  dt { color: var(--muted); font-size: 12px; }
  dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
  .fingerprint { font-size: 12px; }
</style>
