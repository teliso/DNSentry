<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import SaveBar from '../components/SaveBar.svelte';
  import { store } from '../lib/store.svelte';
  import AccessSection from '../sections/AccessSection.svelte';
  import EncryptionSection from '../sections/EncryptionSection.svelte';
  import ListenSection from '../sections/ListenSection.svelte';
  import LoggingSection from '../sections/LoggingSection.svelte';
</script>

<PageHeader title="服务设置" description="监听地址、查询日志、访问控制与加密 DNS。部分设置需要重启服务后才会生效。" />

{#if store.draft}
  <ListenSection config={store.draft} />
  <LoggingSection config={store.draft} />
  <AccessSection config={store.draft} />
  <EncryptionSection config={store.draft} />
  <SaveBar />
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
