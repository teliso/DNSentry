<script lang="ts">
  import { onMount } from 'svelte';
  import Icon, { type IconName } from './components/Icon.svelte';
  import AlertBanners from './components/AlertBanners.svelte';
  import SaveBar from './components/SaveBar.svelte';
  import Toasts from './components/Toasts.svelte';
  import TokenDialog from './components/TokenDialog.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Dns from './pages/Dns.svelte';
  import Filters from './pages/Filters.svelte';
  import Logs from './pages/Logs.svelte';
  import Settings from './pages/Settings.svelte';
  import { router, type Page } from './lib/router.svelte';
  import { store } from './lib/store.svelte';
  import { theme } from './lib/theme.svelte';

  // Monitoring, then filtering, then configuration — left to right.
  const NAV: { page: Page; label: string; icon: IconName }[] = [
    { page: 'overview', label: '概览', icon: 'dashboard' },
    { page: 'logs', label: '日志', icon: 'activity' },
    { page: 'filters', label: '过滤', icon: 'shield' },
    { page: 'dns', label: 'DNS', icon: 'globe' },
    { page: 'settings', label: '设置', icon: 'settings' }
  ];

  const pages = { overview: Dashboard, logs: Logs, filters: Filters, dns: Dns, settings: Settings };
  const Current = $derived(pages[router.current]);

  onMount(() => {
    void store.start();
  });
</script>

<header class="topbar">
  <div class="bar">
    <a class="brand" href={router.href('overview')} aria-label="DNSentry 仪表盘">
      <span class="mark" aria-hidden="true"><Icon name="shield-check" size={17} /></span>
      <strong>DNSentry</strong>
    </a>

    <nav aria-label="主导航">
      {#each NAV as item (item.page)}
        <a href={router.href(item.page)} class:active={router.current === item.page} aria-current={router.current === item.page ? 'page' : undefined}>
          <Icon name={item.icon} size={17} />
          <span>{item.label}</span>
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
    <Current />
  {/key}
  <SaveBar />
</main>

<Toasts />
{#if store.tokenRequired}<TokenDialog />{/if}

<style>
  .topbar {
    position: sticky; top: 0; z-index: 50;
    background: color-mix(in srgb, var(--surface) 88%, transparent);
    backdrop-filter: saturate(1.5) blur(10px);
    border-bottom: 1px solid var(--line);
  }
  .bar { display: flex; align-items: center; gap: 28px; max-width: var(--page-width); height: var(--topbar-height); margin: 0 auto; padding: 0 var(--gutter); }
  .brand { display: flex; align-items: center; gap: 10px; color: var(--ink); text-decoration: none; flex: none; }
  .brand strong { font-size: 16px; letter-spacing: -0.01em; }
  .mark {
    display: grid; place-items: center; width: 30px; height: 30px; border-radius: 9px;
    background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 55%, #7c3aed));
    color: var(--accent-ink); box-shadow: 0 2px 8px color-mix(in srgb, var(--accent) 35%, transparent);
  }

  nav { display: flex; align-items: center; gap: 4px; flex: 1; min-width: 0; }
  nav a {
    display: flex; align-items: center; gap: 8px; padding: 7px 13px; border-radius: 8px;
    color: var(--ink-2); font-weight: 500; text-decoration: none; white-space: nowrap;
    transition: background 0.12s, color 0.12s;
  }
  nav a :global(svg) { color: var(--muted); transition: color 0.12s; }
  nav a:hover { background: var(--surface-2); color: var(--ink); }
  nav a.active { background: var(--accent-soft); color: var(--accent); }
  nav a.active :global(svg) { color: var(--accent); }

  .tools { display: flex; align-items: center; gap: 8px; flex: none; margin-left: auto; }
  .conn { display: flex; align-items: center; gap: 7px; color: var(--ink-2); font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 0 3px var(--ok-soft); }
  .dot.off { background: var(--danger); box-shadow: 0 0 0 3px var(--danger-soft); }

  main { display: flex; flex-direction: column; gap: 20px; max-width: var(--page-width); margin: 0 auto; padding: 28px var(--gutter) 56px; }

  @media (max-width: 900px) {
    /* backdrop-filter would make the header the containing block of the fixed tab bar */
    .topbar { backdrop-filter: none; background: var(--surface); }
    nav {
      position: fixed; z-index: 50; left: 0; right: 0; bottom: 0; gap: 0;
      padding: 0 4px env(safe-area-inset-bottom);
      background: var(--surface); border-top: 1px solid var(--line);
    }
    nav a { flex: 1; flex-direction: column; justify-content: center; gap: 2px; padding: 8px 0 7px; border-radius: 0; font-size: 11px; background: none; }
    nav a:hover { background: none; }
    nav a.active { background: none; }
    nav a.active::before { content: ''; position: absolute; top: -1px; width: 28px; height: 2px; border-radius: 2px; background: var(--accent); }
    nav a { position: relative; }
    main { padding-top: 18px; padding-bottom: 96px; gap: 16px; }
  }
  @media (max-width: 380px) { .conn-text { display: none; } }
</style>
