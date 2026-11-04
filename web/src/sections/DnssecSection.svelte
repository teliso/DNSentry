<script lang="ts">
  import Card from '../components/Card.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatNumber } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
  const stats = $derived(store.status?.dnssec);
</script>

<Card title="DNSSEC" description="验证解析结果的数字签名，防止被伪造或篡改；验证失败的域名会返回 SERVFAIL。">
  {#snippet actions()}
    <span class="badge" class:ok={config.dnssec_validate}>{config.dnssec_validate ? '验证已开启' : '验证已关闭'}</span>
  {/snippet}

  <div class="stack">
    <Switch bind:checked={config.dnssec_validate} label="验证 DNSSEC 签名" description="使用内置的 IANA 根信任锚。个别未正确配置 DNSSEC 的域名可能因此无法解析。" />
    {#if config.dnssec_validate}
      <p class="counters muted tabular">
        已验证 {formatNumber(stats?.secure ?? 0)} · 未签名 {formatNumber(stats?.insecure ?? 0)} · 验证失败 {formatNumber(stats?.bogus ?? 0)} · 无法判定 {formatNumber(stats?.indeterminate ?? 0)}
      </p>
    {/if}
  </div>
</Card>

<style>
  .counters { font-size: 12px; }
</style>
