<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import { toasts } from '../lib/toast.svelte';
  import { store } from '../lib/store.svelte';
  import type { Config, WebTlsSource } from '../lib/types';

  let { config }: { config: Config } = $props();
  const running = $derived(store.status?.web_tls);

  const hasEncryptionCertificate = $derived(
    (config.encryption.certificate.trim() !== '' || config.encryption.certificate_pem.trim() !== '') &&
      (config.encryption.private_key.trim() !== '' || config.encryption.certificate_pem.trim() !== '')
  );

  const SOURCES: { value: WebTlsSource; title: string; text: string }[] = [
    { value: 'auto', title: '自动生成（自签名）', text: '无需准备证书，浏览器会提示不信任。' },
    { value: 'encryption', title: '复用加密 DNS 的证书', text: '与 DoH / DoT 共用同一张证书，用它的域名访问就不会警告。' },
    { value: 'custom', title: '单独指定证书', text: '为控制台使用另一张证书和私钥。' }
  ];

  const port = $derived(config.http_listen.slice(config.http_listen.lastIndexOf(':') + 1));
  const address = $derived(config.web_tls.server_name.trim() ? `https://${config.web_tls.server_name.trim()}${port === '443' ? '' : `:${port}`}` : '');

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toasts.success('已复制');
    } catch {
      toasts.error('无法访问剪贴板，请手动复制');
    }
  }
</script>

<Card title="控制台 HTTPS" description="用 HTTPS 提供控制台，登录密码和会话 Cookie 不再明文传输。证书只认域名，和端口、路径无关：用证书对应的域名打开控制台即可。">
  {#snippet actions()}
    <span class="badge" class:ok={running?.enabled}>{running?.enabled ? '正在使用 HTTPS' : '正在使用 HTTP'}</span>
    <span class="badge warn">重启后生效</span>
  {/snippet}

  <div class="stack">
    <Switch bind:checked={config.web_tls.enabled} label="启用 HTTPS" description="启用后控制台地址变成 https://…；原来的 http:// 地址将无法访问。" />

    {#if config.web_tls.enabled}
      <div class="sources" role="radiogroup" aria-label="证书来源">
        {#each SOURCES as source (source.value)}
          {@const unavailable = source.value === 'encryption' && !hasEncryptionCertificate}
          <label class="source" class:selected={config.web_tls.source === source.value} class:unavailable>
            <input type="radio" name="web_tls_source" value={source.value} bind:group={config.web_tls.source} disabled={unavailable} />
            <strong>{source.title}</strong>
            <small>{unavailable ? '尚未配置加密 DNS 的证书（设置 → 加密 DNS）' : source.text}</small>
          </label>
        {/each}
      </div>

      {#if config.web_tls.source === 'custom'}
        <div class="form-grid two">
          <Field label="证书文件" hint="PEM 格式，可包含中间证书链；更新后自动生效">
            <input class="mono" bind:value={config.web_tls.certificate} placeholder="/etc/ssl/dnsentry/fullchain.pem" spellcheck="false" />
          </Field>
          <Field label="私钥文件" hint="与证书配套的 PEM 私钥">
            <input class="mono" bind:value={config.web_tls.private_key} placeholder="/etc/ssl/dnsentry/privkey.pem" spellcheck="false" />
          </Field>
        </div>
      {/if}

      <Field label="绑定域名（可选）" hint="用哪个域名打开控制台，例如 DoH / DoT 证书对应的域名。选“自动生成”时，证书会包含它；其他来源会检查证书是否匹配。">
        <input class="mono" bind:value={config.web_tls.server_name} placeholder="dns.example.com" autocapitalize="off" spellcheck="false" />
      </Field>
      {#if address}
        <p class="muted small">
          重启后用 <code>{address}</code> 打开控制台。别忘了让这个域名在设备上解析到本机（局域网里可在“DNS → 本地记录”添加一条）。
          <button class="btn ghost sm" type="button" onclick={() => copy(address)}>复制</button>
        </p>
      {/if}
      {#if config.web_tls.source === 'auto'}
        <p class="note">自签名证书保存在配置文件同目录的 <code>web-tls.crt</code> / <code>web-tls.key</code>，包含本机主机名和当前网卡地址。浏览器会提示“不安全”：请核对下面的指纹后选择继续。</p>
      {/if}
    {/if}

    {#if running?.enabled && running.fingerprint}
      <dl class="info">
        <div>
          <dt>当前证书</dt>
          <dd>
            {running.mode === 'self-signed' ? '自签名' : running.mode === 'encryption' ? '加密 DNS 的证书' : '自定义证书'}{running.not_after ? `，有效期至 ${new Date(running.not_after).toLocaleDateString('zh-CN')}` : ''}
          </dd>
        </div>
        {#if running.names?.length}
          <div><dt>适用于</dt><dd class="mono">{running.names.join('、')}</dd></div>
        {/if}
        <div>
          <dt>SHA-256 指纹</dt>
          <dd class="mono fingerprint">{running.fingerprint} <button class="btn ghost sm" type="button" onclick={() => copy(running.fingerprint ?? '')}>复制</button></dd>
        </div>
      </dl>
      {#if running.server_name && !running.covered}
        <p class="warning">正在使用的证书不包含绑定域名 <code>{running.server_name}</code>，用它访问时浏览器会提示证书不匹配。请换用包含该域名的证书。</p>
      {/if}
    {/if}
  </div>
</Card>

<style>
  .sources { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  .source {
    display: flex; flex-direction: column; gap: 2px; padding: 12px 14px; cursor: pointer;
    border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface);
    transition: border-color 0.12s, background 0.12s;
  }
  .source:hover:not(.unavailable) { border-color: var(--line-strong); }
  .source.selected { border-color: var(--accent); background: var(--accent-soft); }
  .source.unavailable { opacity: 0.55; cursor: not-allowed; }
  .source input { position: absolute; opacity: 0; pointer-events: none; }
  .source:focus-within { box-shadow: var(--focus); }
  small { color: var(--muted); }
  .note { padding: 9px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); color: var(--ink-2); }
  .warning { padding: 9px 12px; border-radius: var(--radius-sm); background: var(--warn-soft); color: var(--ink-2); }
  .small { font-size: 12px; }
  .info { display: grid; gap: 10px; margin: 0; }
  dt { color: var(--muted); font-size: 12px; }
  dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
  .fingerprint { font-size: 12px; }
  @media (max-width: 720px) { .sources { grid-template-columns: 1fr; } }
</style>
