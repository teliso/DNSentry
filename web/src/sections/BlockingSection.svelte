<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import type { BlockingMode, Config } from '../lib/types';

  let { config }: { config: Config } = $props();

  const HINTS: Record<BlockingMode, string> = {
    default: '返回 0.0.0.0 或 ::。',
    null_ip: '返回 0.0.0.0 或 ::。',
    nxdomain: '返回 NXDOMAIN，并附带负缓存 SOA。',
    refused: '返回 REFUSED，客户端通常不会缓存。',
    custom_ip: '返回下方自定义的地址。'
  };
</script>

<Card id="sec-blocking" title="拦截响应" description="命中过滤规则时返回给客户端的内容。">
  <div class="form-grid">
    <Field label="拦截模式" hint={HINTS[config.blocking_mode]}>
      <select bind:value={config.blocking_mode}>
        <option value="default">默认（空 IP）</option>
        <option value="nxdomain">NXDOMAIN</option>
        <option value="null_ip">空 IP</option>
        <option value="custom_ip">自定义 IP</option>
        <option value="refused">REFUSED</option>
      </select>
    </Field>
    <Field label="拦截响应 TTL" hint="客户端缓存拦截结果的秒数">
      <div class="unit"><input type="number" min="0" bind:value={config.blocked_response_ttl} /><span>秒</span></div>
    </Field>
    {#if config.blocking_mode === 'custom_ip'}
      <Field label="IPv4 响应地址"><input bind:value={config.blocking_ipv4} placeholder="0.0.0.0" class="mono" /></Field>
      <Field label="IPv6 响应地址"><input bind:value={config.blocking_ipv6} placeholder="::" class="mono" /></Field>
    {/if}
  </div>
</Card>
