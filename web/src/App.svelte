<script lang="ts">
  import { onMount } from 'svelte';
  import Icon, { type IconName } from './components/Icon.svelte';
  import AlertBanners from './components/AlertBanners.svelte';
  import Toasts from './components/Toasts.svelte';
  import TokenDialog from './components/TokenDialog.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import DnsSettings from './pages/DnsSettings.svelte';
  import Filters from './pages/Filters.svelte';
  import Logs from './pages/Logs.svelte';
  import Records from './pages/Records.svelte';
  import Service from './pages/Service.svelte';
  import Sources from './pages/Sources.svelte';
  import { router, type Route } from './lib/router.svelte';
  import { store } from './lib/store.svelte';
  import { theme } from './lib/theme.svelte';

  // Monitoring, then filtering, then configuration — left to right.
  const NAV: { route: Route; label: string; short: string; icon: IconName }[] = [
    { route: 'overview', label: '仪表盘', short: '概览', icon: 'dashboard' },
    { route: 'logs', label: '查询日志', short: '日志', icon: 'activity' },
    { route: 'filters', label: '过滤规则', short: '规则', icon: 'shield' },
    { route: 'sources', label: '规则源', short: '订阅', icon: 'download' },
    { route: 'records', label: '本地记录', short: '记录', icon: 'list' },
    { route: 'dns', label: 'DNS 设置', short: 'DNS', icon: 'globe' },
    { route: 'settings', label: '服务设置', short: '设置', icon: 'settings' }
  ];

  const pages = { overview: Dashboard, logs: Logs, filters: Filters, sources: Sources, records: Records, dns: DnsSettings, settings: Service };
  const Page = $derived(pages[router.current]);

  onMount(() => {
    void store.start();
  });
</script>

<header class="topbar">
  <div class="bar">
    <a class="brand" href="#overview" aria-label="DNSentry 仪表盘">
      <span class="mark" aria-hidden="true"><Icon name="shield-check" size={17} /></span>
      <strong>DNSentry</strong>
    </a>

    <nav aria-label="主导航">
      {#each NAV as item (item.route)}
        <a href="#{item.route}" class:active={router.current === item.route} aria-current={router.current === item.route ? 'page' : undefined}>
          <Icon name={item.icon} size={17} />
          <span class="full">{item.label}</span>
          <span class="short">{item.short}</span>
        </a>
      {/each}
    </nav>

    <div class="tools">
      <span class="conn" role="status" title={store.status?.version ? `版本 ${store.status.version}` : undefined}>
        <span class="dot" class:off={!store.online}></span>
        <span class="conn-text">{store.online ? '运行中' : store.status ? '连接中断' : '连接中…'}</span>
      </span>
      <button class="btn ghost sm icon" type="button" onclick={theme.toggle} aria-label={theme.current === 'dark' ? '切换到浅色主题' : '切换到深色主题'}>
        <Icon name={theme.current === 'dark' ? 'sun' : 'moon'} />
      </button>
    </div>
  </div>
</header>

<main>
  <AlertBanners />
  {#key router.current}
    <Page />
  {/key}
</main>

<Toasts />
{#if store.tokenRequired}<TokenDialog />{/if}

<style>
  .topbar {
    position: sticky; top: 0; z-index: 50;
    background: color-mix(in srgb, var(--surface) 92%, transparent);
    backdrop-filter: saturate(1.4) blur(8px);
    border-bottom: 1px solid var(--line);
  }
  .bar { display: flex; align-items: center; gap: 24px; max-width: var(--page-width); height: var(--topbar-height); margin: 0 auto; padding: 0 32px; }
  .brand { display: flex; align-items: center; gap: 9px; color: var(--ink); text-decoration: none; flex: none; }
  .brand strong { font-size: 15px; }
  .mark { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; background: var(--accent); color: var(--accent-ink); }

  nav { display: flex; align-items: stretch; align-self: stretch; gap: 2px; flex: 1; min-width: 0; }
  nav a {
    position: relative; display: flex; align-items: center; gap: 7px; padding: 0 11px;
    color: var(--ink-2); font-weight: 500; text-decoration: none; white-space: nowrap;
  }
  nav a :global(svg) { color: var(--muted); }
  nav a:hover { color: var(--ink); }
  nav a.active { color: var(--accent); }
  nav a.active :global(svg) { color: var(--accent); }
  nav a.active::after { content: ''; position: absolute; left: 8px; right: 8px; bottom: -1px; height: 2px; border-radius: 2px; background: var(--accent); }
  .short { display: none; }

  .tools { display: flex; align-items: center; gap: 8px; flex: none; }
  .conn { display: flex; align-items: center; gap: 7px; color: var(--ink-2); font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 0 3px var(--ok-soft); }
  .dot.off { background: var(--danger); box-shadow: 0 0 0 3px var(--danger-soft); }

  main { display: flex; flex-direction: column; gap: 20px; max-width: var(--page-width); margin: 0 auto; padding: 28px 32px 56px; }

  @media (max-width: 1180px) {
    nav a :global(svg) { display: none; }
    nav a { padding: 0 9px; }
    .bar { gap: 16px; padding: 0 20px; }
  }
  @media (max-width: 900px) {
    /* backdrop-filter would make the header the containing block of the fixed tab bar */
    .topbar { backdrop-filter: none; background: var(--surface); }
    .bar { padding: 0 16px; }
    nav {
      position: fixed; z-index: 50; left: 0; right: 0; bottom: 0; gap: 0;
      padding-bottom: env(safe-area-inset-bottom);
      background: var(--surface); border-top: 1px solid var(--line);
    }
    nav a { flex: 1; flex-direction: column; justify-content: center; gap: 2px; padding: 8px 0 7px; font-size: 11px; }
    nav a :global(svg) { display: block; }
    nav a.active::after { top: -1px; bottom: auto; }
    .full { display: none; }
    .short { display: inline; }
    .tools { margin-left: auto; }
    main { padding: 18px 16px 96px; gap: 16px; }
  }
  @media (max-width: 380px) { .conn-text { display: none; } }
</style>
