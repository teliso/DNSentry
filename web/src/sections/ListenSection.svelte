<script lang="ts">
  import Card from '../components/Card.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card title="普通 DNS 服务" description="每个地址同时绑定 UDP 与 TCP，首项作为兼容主地址，最多 16 个。监听地址变更需要重启服务。">
  {#snippet actions()}
    <button class="btn sm" type="button" disabled={store.busy} onclick={() => confirm('用上一次保存前的配置覆盖当前配置？') && store.restoreConfig()}>恢复上次配置</button>
  {/snippet}
  <ListEditor label="监听地址" hint="生产环境通常用 :53；开发环境可使用其他端口" placeholder=":53&#10;192.0.2.10:53" maxItems={16} code bind:values={config.dns_listens} />
</Card>
