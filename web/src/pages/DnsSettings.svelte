<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import SaveBar from '../components/SaveBar.svelte';
  import SectionNav from '../components/SectionNav.svelte';
  import { store } from '../lib/store.svelte';
  import BlockingSection from '../sections/BlockingSection.svelte';
  import CacheSection from '../sections/CacheSection.svelte';
  import DnssecSection from '../sections/DnssecSection.svelte';
  import ResolutionSection from '../sections/ResolutionSection.svelte';
  import RoutesSection from '../sections/RoutesSection.svelte';
  import UpstreamsSection from '../sections/UpstreamsSection.svelte';

  const SECTIONS = [
    { id: 'sec-upstreams', label: '上游服务器' },
    { id: 'sec-routes', label: '域名分流' },
    { id: 'sec-cache', label: '缓存' },
    { id: 'sec-behavior', label: '解析行为' },
    { id: 'sec-blocking', label: '拦截响应' },
    { id: 'sec-dnssec', label: 'DNSSEC' }
  ];
</script>

<PageHeader title="DNS 设置" description="上游与域名分流、缓存、解析行为、被拦截请求的响应方式与 DNSSEC。修改在保存后立即生效。" />

{#if store.draft}
  <SectionNav sections={SECTIONS} />
  <UpstreamsSection config={store.draft} />
  <RoutesSection config={store.draft} />
  <CacheSection config={store.draft} />
  <ResolutionSection config={store.draft} />
  <BlockingSection config={store.draft} />
  <DnssecSection config={store.draft} />
  <SaveBar />
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
