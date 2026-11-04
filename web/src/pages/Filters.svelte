<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Tabs from '../components/Tabs.svelte';
  import { formatCompact } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';
  import BlockingSection from '../sections/BlockingSection.svelte';
  import ServicesSection from '../sections/ServicesSection.svelte';
  import RulesPanel from '../panels/RulesPanel.svelte';
  import SourcesPanel from '../panels/SourcesPanel.svelte';

  const tabs = $derived([
    { id: 'sources', label: '规则源', badge: String(store.sources.filter((source) => source.enabled).length) },
    { id: 'rules', label: '规则', badge: formatCompact(store.status?.rules ?? 0) },
    { id: 'services', label: '服务屏蔽', badge: store.saved?.blocked_services.length ? String(store.saved.blocked_services.length) : undefined },
    { id: 'blocking', label: '拦截响应' }
  ]);
</script>

<PageHeader title="过滤" description="决定哪些域名被拦截或放行：订阅规则源、管理自己的规则、屏蔽整个服务、强制安全搜索，并可检测任一域名为什么被拦截。" />
<Tabs page="filters" {tabs} />

{#if router.tab === 'sources'}
  <SourcesPanel />
{:else if router.tab === 'rules'}
  <RulesPanel />
{:else if store.draft}
  {#if router.tab === 'services'}
    <ServicesSection config={store.draft} />
  {:else}
    <BlockingSection config={store.draft} />
  {/if}
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
