<script lang="ts">
  import Tabs from '../components/Tabs.svelte';
  import { formatCompact } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';
  import BlockingSection from '../sections/BlockingSection.svelte';
  import ScheduleSection from '../sections/ScheduleSection.svelte';
  import ServicesSection from '../sections/ServicesSection.svelte';
  import RulesPanel from '../panels/RulesPanel.svelte';
  import SourcesPanel from '../panels/SourcesPanel.svelte';

  const tabs = $derived([
    { id: 'rules', label: '规则', badge: formatCompact(store.status?.rules ?? 0) },
    { id: 'sources', label: '规则源', badge: String(store.sources.filter((source) => source.enabled).length) },
    { id: 'services', label: '服务屏蔽', badge: store.saved?.blocked_services.length ? String(store.saved.blocked_services.length) : undefined },
    { id: 'schedule', label: '计划', badge: store.status?.active_schedules?.length ? '生效中' : store.saved?.schedule.rules.length ? String(store.saved.schedule.rules.length) : undefined },
    { id: 'blocking', label: '拦截响应' }
  ]);
</script>

<Tabs page="filters" {tabs} />

{#if router.tab === 'rules'}
  <RulesPanel />
{:else if router.tab === 'sources'}
  <SourcesPanel />
{:else if store.draft}
  {#if router.tab === 'services'}
    <ServicesSection config={store.draft} />
  {:else if router.tab === 'schedule'}
    <ScheduleSection config={store.draft} />
  {:else}
    <BlockingSection config={store.draft} />
  {/if}
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
