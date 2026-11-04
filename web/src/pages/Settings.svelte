<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Tabs from '../components/Tabs.svelte';
  import { router } from '../lib/router.svelte';
  import { store } from '../lib/store.svelte';
  import AccountSection from '../sections/AccountSection.svelte';
  import AccessSection from '../sections/AccessSection.svelte';
  import EncryptionSection from '../sections/EncryptionSection.svelte';
  import WebTlsSection from '../sections/WebTlsSection.svelte';
  import ListenSection from '../sections/ListenSection.svelte';
  import LoggingSection from '../sections/LoggingSection.svelte';
  import MaintenanceSection from '../sections/MaintenanceSection.svelte';

  const tabs = [
    { id: 'network', label: '网络与访问' },
    { id: 'account', label: '控制台登录' },
    { id: 'encryption', label: '加密 DNS' },
    { id: 'logging', label: '日志' },
    { id: 'maintenance', label: '维护' }
  ];
</script>

<PageHeader title="设置" description="服务对外提供的方式、谁可以使用它，以及日志与维护。监听、加密和日志存储的改动需要重启服务。" />
<Tabs page="settings" {tabs} />

{#if router.tab === 'maintenance'}
  <MaintenanceSection />
{:else if router.tab === 'account'}
  <AccountSection />
{:else if store.draft}
  {#if router.tab === 'network'}
    <ListenSection config={store.draft} />
    <WebTlsSection config={store.draft} />
    <AccessSection config={store.draft} />
  {:else if router.tab === 'encryption'}
    <EncryptionSection config={store.draft} />
  {:else}
    <LoggingSection config={store.draft} />
  {/if}
{:else}
  <p class="muted">正在读取配置…</p>
{/if}
