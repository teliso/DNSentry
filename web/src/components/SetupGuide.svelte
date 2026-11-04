<script lang="ts">
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';

  let { onclose }: { onclose: () => void } = $props();

  const LOOPBACK = /^(localhost|127\.|\[?::1\]?$)/;
  const opened = window.location.hostname;
  const local = LOOPBACK.test(opened);
  const host = local ? '<服务器的局域网 IP>' : opened;

  const portOf = (listen: string) => listen.slice(listen.lastIndexOf(':') + 1);
  const dnsPort = $derived(portOf(store.status?.dns_listens?.[0] ?? ':53'));
  const encryption = $derived(store.saved?.encryption);

  const addresses = $derived.by(() => {
    const items: { label: string; value: string; note?: string }[] = [
      { label: '普通 DNS', value: dnsPort === '53' ? host : `${host}:${dnsPort}`, note: dnsPort === '53' ? undefined : '多数设备只能使用 53 端口，请在“设置 → 网络与访问”中改为 :53' }
    ];
    if (encryption?.enabled) {
      if (encryption.dot_listens.length) items.push({ label: 'DNS over TLS', value: `tls://${host}${portOf(encryption.dot_listens[0]) === '853' ? '' : `:${portOf(encryption.dot_listens[0])}`}` });
      if (encryption.doh_listens.length) items.push({ label: 'DNS over HTTPS', value: `https://${host}${portOf(encryption.doh_listens[0]) === '443' ? '' : `:${portOf(encryption.doh_listens[0])}`}/dns-query` });
      if (encryption.doq_listens.length) items.push({ label: 'DNS over QUIC', value: `quic://${host}${portOf(encryption.doq_listens[0]) === '853' ? '' : `:${portOf(encryption.doq_listens[0])}`}` });
    }
    return items;
  });

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toasts.success('已复制');
    } catch {
      toasts.error('无法访问剪贴板，请手动复制');
    }
  }
</script>

<Modal title="接入指引" {onclose}>
  <div class="guide">
    <p>让设备使用 DNSentry，只需要把它们的 DNS 服务器设成下面的地址。</p>
    {#if local}
      <p class="note"><Icon name="info" size={14} />你正在本机上打开控制台。设备需要使用的是运行 DNSentry 的这台机器在<strong>局域网中的 IP 地址</strong>（建议在路由器里给它固定 IP）。</p>
    {/if}
    <ul class="addresses">
      {#each addresses as item (item.label)}
        <li>
          <span class="muted">{item.label}</span>
          <code>{item.value}</code>
          {#if !local}<button class="btn ghost sm icon" type="button" aria-label="复制 {item.label} 地址" onclick={() => copy(item.value)}><Icon name="copy" /></button>{/if}
          {#if item.note}<small>{item.note}</small>{/if}
        </li>
      {/each}
    </ul>
    <h3>怎么设置</h3>
    <ol>
      <li><strong>整个网络（推荐）：</strong>在路由器的 DHCP / LAN 设置里，把“DNS 服务器”设为上面的地址，只填一个，不要再填备用 DNS，否则设备会绕过过滤。</li>
      <li><strong>单个设备：</strong>在系统的网络设置里手动指定 DNS。手机的“私人 DNS”可填 DoT 主机名（需要有效证书）。</li>
      <li><strong>验证：</strong>设备上网后，回到“日志”页，应该能看到它的请求。</li>
    </ol>
  </div>
  {#snippet footer()}<button class="btn primary" type="button" onclick={onclose}>知道了</button>{/snippet}
</Modal>

<style>
  .guide { display: flex; flex-direction: column; gap: 12px; }
  .note { display: flex; gap: 8px; align-items: flex-start; padding: 9px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); color: var(--ink-2); }
  .note :global(svg) { flex: none; margin-top: 3px; color: var(--accent); }
  .addresses { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .addresses li { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 10px; padding: 9px 12px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .addresses li > span { width: 110px; flex: none; font-size: 13px; }
  .addresses code { flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: 14px; font-weight: 600; }
  .addresses small { flex-basis: 100%; color: var(--warn); }
  ol { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: 8px; }
</style>
