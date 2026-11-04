<script lang="ts">
  import Tabs from '../components/Tabs.svelte';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';
  import CacheSection from '../sections/CacheSection.svelte';
  import DnssecSection from '../sections/DnssecSection.svelte';
  import ResolutionSection from '../sections/ResolutionSection.svelte';
  import RoutesSection from '../sections/RoutesSection.svelte';
  import UpstreamsSection from '../sections/UpstreamsSection.svelte';
  import RecordsPanel from '../panels/RecordsPanel.svelte';

  const tabs = $derived([
    { id: 'upstreams', label: '上游' },
    { id: 'routes', label: '域名分流', badge: store.saved?.upstream_routes.length ? String(store.saved.upstream_routes.length) : undefined },
    { id: 'records', label: '本地记录', badge: store.saved?.local_records.length ? String(store.saved.local_records.length) : undefined },
    { id: 'cache', label: '缓存' },
    { id: 'advanced', label: '高级' }
  ]);
</script>

<Tabs page="dns" {tabs} />

{#if router.tab === 'records'}
  <RecordsPanel />
{:else if store.draft}
  {#if router.tab === 'upstreams'}
    <UpstreamsSection config={store.draft} />
  {:else if router.tab === 'routes'}
    <RoutesSection config={store.draft} />
  {:else if router.tab === 'cache'}
    <CacheSection config={store.draft} />
  {:else}
    <ResolutionSection config={store.draft} />
    <DnssecSection config={store.draft} />
  {/if}
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
