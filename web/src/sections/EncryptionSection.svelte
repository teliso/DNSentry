<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import Switch from '../components/Switch.svelte';
  import { toasts } from '../lib/toast.svelte';
  import { store } from '../lib/store.svelte';
  import type { Config, SecureProtocol } from '../lib/types';

  let { config }: { config: Config } = $props();

  const PROTOCOLS: { key: SecureProtocol; name: string; desc: string; port: string }[] = [
    { key: 'dot', name: 'DoT', desc: 'DNS over TLS', port: ':853' },
    { key: 'doh', name: 'DoH', desc: 'DNS over HTTPS（/dns-query）', port: ':443' },
    { key: 'doh3', name: 'DoH3', desc: 'DNS over HTTP/3', port: ':443' },
    { key: 'doq', name: 'DoQ', desc: 'DNS over QUIC', port: ':853' }
  ];

  const encryption = $derived(config.encryption);
  const dnscrypt = $derived(config.encryption.dnscrypt);
  const runtime = $derived(store.status?.dnscrypt);

  async function copyStamp() {
    if (!runtime?.stamp) return;
    try {
      await navigator.clipboard.writeText(runtime.stamp);
      toasts.success('已复制 DNSCrypt stamp');
    } catch {
      toasts.error('复制失败，请手动选择文本');
    }
  }
</script>

<Card title="加密 DNS 服务" description="对外提供 DoT、DoH、DoH3 与 DoQ。证书、私钥或监听变更后需要重启服务。">
  {#snippet actions()}
    <span class="badge" class:ok={encryption.enabled}>{encryption.enabled ? '已启用' : '未启用'}</span>
  {/snippet}

  <div class="stack">
    <Switch bind:checked={encryption.enabled} label="启用加密 DNS 监听" description="启用后才会绑定下方各协议的监听地址。" />

    {#if encryption.enabled}
      <div class="form-grid two">
        <Field label="TLS 证书路径"><input class="mono" bind:value={encryption.certificate} placeholder="data/tls/server.crt" /></Field>
        <Field label="TLS 私钥路径"><input class="mono" bind:value={encryption.private_key} placeholder="data/tls/server.key" /></Field>
        <Field label="TLS 证书 PEM" hint="填写后优先于路径">
          <textarea class="mono" rows="4" bind:value={encryption.certificate_pem} spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        </Field>
        <Field label="TLS 私钥 PEM" hint="私钥不会通过 API 返回；留空则保持现有私钥">
          <textarea class="mono" rows="4" bind:value={encryption.private_key_pem} spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
        </Field>
      </div>

      <hr class="divider" />
      <div class="protocols">
        {#each PROTOCOLS as protocol (protocol.key)}
          <ListEditor
            label="{protocol.name} 监听地址"
            hint="{protocol.desc}，默认 {protocol.port}"
            placeholder={protocol.port}
            code
            rows={2}
            maxItems={16}
            bind:values={encryption[`${protocol.key}_listens`]}
          />
        {/each}
      </div>
    {/if}
  </div>
</Card>

<Card title="DNSCrypt v2" description="Provider 密钥首次启用时自动生成；服务运行后可在此复制客户端 stamp。">
  {#snippet actions()}
    <span class="badge" class:ok={runtime?.running}>{runtime?.running ? '运行中' : dnscrypt.enabled ? '重启后生效' : '未启用'}</span>
  {/snippet}

  <div class="stack">
    <Switch bind:checked={dnscrypt.enabled} label="启用 DNSCrypt" description="UDP 与 TCP 都会绑定监听地址。" />
    {#if runtime?.stamp}
      <div class="stamp">
        <code>{runtime.stamp}</code>
        <button class="btn sm" type="button" onclick={copyStamp}>复制</button>
      </div>
    {/if}
    {#if dnscrypt.enabled}
      <div class="form-grid two">
        <ListEditor label="监听地址" hint="默认 :443" placeholder=":443" code rows={2} bind:values={dnscrypt.listens} />
        <div class="stack">
          <Field label="Provider 名称"><input class="mono" bind:value={dnscrypt.provider_name} placeholder="vigordns" /></Field>
          <Field label="证书有效期"><div class="unit"><input type="number" min="1" bind:value={dnscrypt.certificate_ttl_hours} /><span>小时</span></div></Field>
        </div>
        <Field label="Provider 私钥" hint="32 字节种子或 64 字节私钥（十六进制）；留空保持现有密钥">
          <input class="mono" type="password" autocomplete="off" bind:value={dnscrypt.private_key} />
        </Field>
        <Field label="Resolver secret" hint="留空时首次启用自动生成">
          <input class="mono" type="password" autocomplete="off" bind:value={dnscrypt.resolver_secret} />
        </Field>
      </div>
    {/if}
  </div>
</Card>

<style>
  .protocols { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
  .stamp { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--radius-sm); }
  .stamp code { flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: 12px; }
  @media (max-width: 720px) { .protocols { grid-template-columns: 1fr; } }
</style>
