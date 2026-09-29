<script lang="ts">
  import Card from '../components/Card.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card id="sec-listen" title="DNS 监听" description="每个地址同时绑定 UDP 与 TCP，首项作为兼容主地址，最多 16 个。监听地址变更需要重启服务。">
  <div class="stack">
  <ListEditor label="监听地址" hint="生产环境通常用 :53；开发环境可使用其他端口" placeholder=":53&#10;192.0.2.10:53" maxItems={16} code bind:values={config.dns_listens} />
  <p class="muted web">
    Web 控制台监听 <code>{config.http_listen}</code>。该地址只能在配置文件中修改；绑定非回环地址时必须设置
    <code>DNSENTRY_ALLOW_PUBLIC_WEB=1</code> 和 <code>DNSENTRY_API_TOKEN</code>。
  </p>
  </div>
</Card>

<style>
  .web { font-size: 13px; }
</style>
