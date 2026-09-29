<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import Switch from '../components/Switch.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card title="访问控制与安全" description="限制客户端来源、控制资源使用，并阻止公网域名返回私网地址。">
  <div class="stack">
    <div class="form-grid two">
      <ListEditor label="允许的客户端" hint="IP 或 CIDR；留空允许所有" placeholder="192.0.2.0/24" code rows={3} bind:values={config.access.allowed_clients} />
      <ListEditor label="拒绝的客户端" hint="拒绝列表优先于允许列表" placeholder="192.0.2.10" code rows={3} bind:values={config.access.denied_clients} />
    </div>
    <div class="form-grid two">
      <Field label="单客户端速率限制" hint="每秒查询数，0 表示不限制">
        <div class="unit"><input type="number" min="0" bind:value={config.access.client_rate_limit_qps} /><span>QPS</span></div>
      </Field>
      <Field label="最大并发查询" hint="超过上限返回 SERVFAIL">
        <div class="unit"><input type="number" min="1" bind:value={config.access.max_concurrent_queries} /><span>个</span></div>
      </Field>
    </div>
    <hr class="divider" />
    <Switch bind:checked={config.access.rebinding_protection} label="DNS Rebinding 防护" description="阻止公网域名返回私网、回环或链路本地地址。" />
    {#if config.access.rebinding_protection}
      <ListEditor label="Rebinding 例外域名" hint="可信的内网域名" placeholder="home.arpa" rows={3} bind:values={config.access.rebinding_allow_domains} />
    {/if}
  </div>
</Card>
