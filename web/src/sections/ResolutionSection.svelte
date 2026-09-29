<script lang="ts">
  import Card from '../components/Card.svelte';
  import Switch from '../components/Switch.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card id="sec-behavior" title="解析行为" description="影响所有客户端的解析方式，保存后立即生效。">
  <div class="stack">
    <Switch
      bind:checked={config.private_reverse}
      label="本地处理私网反向解析（PTR）"
      description="10.x、172.16–31.x、192.168.x、fc00::/7 等地址的反向查询由本机应答：能匹配本地记录的返回主机名，其余返回 NXDOMAIN，不再发往公网上游泄露内网信息。已配置域名分流的反向区除外。"
    />
    <Switch
      bind:checked={config.block_aaaa}
      label="不解析 IPv6（AAAA）"
      description="对 AAAA 查询直接返回空应答，适合没有 IPv6 出口的网络，避免连接超时后才回退到 IPv4。本地记录中的 AAAA 仍会返回。"
    />
  </div>
</Card>
