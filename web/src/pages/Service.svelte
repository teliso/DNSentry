<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import SaveBar from '../components/SaveBar.svelte';
  import SectionNav from '../components/SectionNav.svelte';
  import { store } from '../lib/store.svelte';
  import AccessSection from '../sections/AccessSection.svelte';
  import EncryptionSection from '../sections/EncryptionSection.svelte';
  import ListenSection from '../sections/ListenSection.svelte';
  import LoggingSection from '../sections/LoggingSection.svelte';
  import MaintenanceSection from '../sections/MaintenanceSection.svelte';

  const SECTIONS = [
    { id: 'sec-listen', label: '监听' },
    { id: 'sec-encryption', label: '加密 DNS' },
    { id: 'sec-dnscrypt', label: 'DNSCrypt' },
    { id: 'sec-access', label: '访问控制' },
    { id: 'sec-logging', label: '查询日志' },
    { id: 'sec-maintenance', label: '配置历史' }
  ];
</script>

<PageHeader title="服务设置" description="服务对外提供的方式、谁可以使用它，以及日志与维护。监听、加密和日志存储的改动需要重启服务。" />

{#if store.draft}
  <SectionNav sections={SECTIONS} />
  <ListenSection config={store.draft} />
  <EncryptionSection config={store.draft} />
  <AccessSection config={store.draft} />
  <LoggingSection config={store.draft} />
  <MaintenanceSection />
  <SaveBar />
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
