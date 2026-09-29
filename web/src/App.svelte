<script lang="ts">
  import { onMount } from 'svelte';
  import Icon, { type IconName } from './components/Icon.svelte';
  import Toasts from './components/Toasts.svelte';
  import TokenDialog from './components/TokenDialog.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Filters from './pages/Filters.svelte';
  import Logs from './pages/Logs.svelte';
  import Resolver from './pages/Resolver.svelte';
  import Service from './pages/Service.svelte';
  import Sources from './pages/Sources.svelte';
  import { router, type Route } from './lib/router.svelte';
  import { store } from './lib/store.svelte';
  import { theme } from './lib/theme.svelte';

  const NAV: { group: string; items: { route: Route; label: string; short: string; icon: IconName }[] }[] = [
    {
      group: '监控',
      items: [
        { route: 'overview', label: '仪表盘', short: '仪表盘', icon: 'dashboard' },
        { route: 'logs', label: '查询日志', short: '日志', icon: 'activity' }
      ]
    },
    {
      group: '过滤',
      items: [
        { route: 'filters', label: '过滤规则', short: '规则', icon: 'shield' },
        { route: 'sources', label: '规则源', short: '订阅', icon: 'download' }
      ]
    },
    {
      group: '配置',
      items: [
        { route: 'upstreams', label: '上游与解析', short: '解析', icon: 'globe' },
        { route: 'settings', label: '服务设置', short: '服务', icon: 'settings' }
      ]
    }
  ];

  const pages = { overview: Dashboard, logs: Logs, filters: Filters, sources: Sources, upstreams: Resolver, settings: Service };
  const Page = $derived(pages[router.current]);

  onMount(() => {
    void store.start();
  });
</script>

<div class="shell">
  <aside>
    <a class="brand" href="#overview" aria-label="VigorDNS 仪表盘">
      <span class="mark" aria-hidden="true"><Icon name="shield-check" size={18} /></span>
      <span><strong>VigorDNS</strong><small>DNS 过滤与解析</small></span>
    </a>

    <nav aria-label="主导航">
      {#each NAV as section (section.group)}
        <div class="group">
          <span class="group-name">{section.group}</span>
          {#each section.items as item (item.route)}
            <a href="#{item.route}" class:active={router.current === item.route} aria-current={router.current === item.route ? 'page' : undefined}>
              <Icon name={item.icon} size={18} />
              <span class="full">{item.label}</span>
              <span class="short">{item.short}</span>
            </a>
          {/each}
        </div>
      {/each}
    </nav>

    <div class="foot">
      <div class="conn" role="status">
        <span class="dot" class:off={!store.online}></span>
        <span>{store.online ? '服务运行中' : store.status ? '连接中断' : '连接中…'}</span>
      </div>
      <button class="btn ghost sm icon" type="button" onclick={theme.toggle} aria-label={theme.current === 'dark' ? '切换到浅色主题' : '切换到深色主题'}>
        <Icon name={theme.current === 'dark' ? 'sun' : 'moon'} />
      </button>
    </div>
  </aside>

  <main>
    <div class="page">
      <Page />
    </div>
  </main>
</div>

<Toasts />
{#if store.tokenRequired}<TokenDialog />{/if}

<style>
  .shell { display: grid; grid-template-columns: 236px minmax(0, 1fr); min-height: 100dvh; }

  aside {
    position: sticky; top: 0; height: 100dvh;
    display: flex; flex-direction: column; gap: 22px; padding: 18px 12px 14px;
    background: var(--surface); border-right: 1px solid var(--line);
  }
  .brand { display: flex; align-items: center; gap: 10px; padding: 2px 8px; color: var(--ink); text-decoration: none; }
  .brand span:last-child { display: flex; flex-direction: column; line-height: 1.25; }
  .brand small { color: var(--muted); }
  .mark { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 9px; background: var(--accent); color: var(--accent-ink); }

  nav { display: flex; flex-direction: column; gap: 18px; flex: 1; overflow-y: auto; }
  .group { display: flex; flex-direction: column; gap: 2px; }
  .group-name { padding: 0 10px 4px; color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: 0.06em; }
  nav a {
    display: flex; align-items: center; gap: 10px; padding: 8px 10px;
    border-radius: var(--radius-sm); color: var(--ink-2); font-weight: 500; text-decoration: none;
  }
  nav a:hover { background: var(--surface-2); color: var(--ink); }
  nav a.active { background: var(--accent-soft); color: var(--accent); }
  .short { display: none; }

  .foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 10px 8px 0; border-top: 1px solid var(--line); }
  .conn { display: flex; align-items: center; gap: 8px; color: var(--ink-2); font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 0 3px var(--ok-soft); }
  .dot.off { background: var(--danger); box-shadow: 0 0 0 3px var(--danger-soft); }

  main { min-width: 0; }
  .page { display: flex; flex-direction: column; gap: 20px; max-width: 1180px; margin: 0 auto; padding: 28px 32px 48px; }

  @media (max-width: 860px) {
    .shell { display: block; }
    aside {
      position: fixed; z-index: 50; top: auto; bottom: 0; left: 0; right: 0; height: auto;
      flex-direction: row; gap: 0; padding: 0 4px env(safe-area-inset-bottom);
      border-right: 0; border-top: 1px solid var(--line);
    }
    .brand, .foot, .group-name { display: none; }
    nav { flex-direction: row; gap: 0; overflow: visible; }
    .group { flex-direction: row; gap: 0; flex: 1; }
    nav { flex: 1; }
    nav a { flex: 1; flex-direction: column; gap: 2px; padding: 8px 2px 7px; border-radius: 0; font-size: 11px; text-align: center; }
    nav a.active { background: transparent; box-shadow: inset 0 2px 0 var(--accent); }
    .full { display: none; }
    .short { display: inline; }
    .page { padding: 18px 16px 96px; gap: 16px; }
  }
</style>
