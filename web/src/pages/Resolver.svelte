<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import SaveBar from '../components/SaveBar.svelte';
  import { store } from '../lib/store.svelte';
  import BlockingSection from '../sections/BlockingSection.svelte';
  import CacheSection from '../sections/CacheSection.svelte';
  import DnssecSection from '../sections/DnssecSection.svelte';
  import LocalRecordsSection from '../sections/LocalRecordsSection.svelte';
  import UpstreamsSection from '../sections/UpstreamsSection.svelte';
</script>

<PageHeader title="上游与解析" description="管理上游服务器、缓存、拦截响应、DNSSEC 与本地记录。修改在保存后才会生效。" />

{#if store.draft}
  <UpstreamsSection config={store.draft} />
  <CacheSection config={store.draft} />
  <BlockingSection config={store.draft} />
  <DnssecSection config={store.draft} />
  <LocalRecordsSection config={store.draft} />
  <SaveBar />
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
