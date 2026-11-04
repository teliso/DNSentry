<script lang="ts">
  import Tabs from '../components/Tabs.svelte';
  import { router } from '../lib/router.svelte';
  import ProgramLog from './ProgramLog.svelte';
  import QueryLog from './QueryLog.svelte';

  const tabs = [
    { id: 'queries', label: 'DNS 查询' },
    { id: 'program', label: '程序日志' }
  ];
</script>

<Tabs page="logs" {tabs} />

{#if router.tab === 'program'}
  <ProgramLog />
{:else}
  <QueryLog />
{/if}
