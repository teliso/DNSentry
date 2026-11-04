<script lang="ts">
  import Card from '../components/Card.svelte';
  import Switch from '../components/Switch.svelte';
  import { api } from '../lib/api';
  import { toasts } from '../lib/toast.svelte';
  import type { Config, ServiceInfo } from '../lib/types';

  let { config }: { config: Config } = $props();

  let catalog = $state<ServiceInfo[]>([]);
  api
    .services()
    .then((list) => (catalog = list))
    .catch((cause) => toasts.error(cause instanceof Error ? cause.message : '读取服务列表失败'));

  const groups = $derived.by(() => {
    const result: { name: string; items: ServiceInfo[] }[] = [];
    for (const service of catalog) {
      let group = result.find((item) => item.name === service.group);
      if (!group) result.push((group = { name: service.group, items: [] }));
      group.items.push(service);
    }
    return result;
  });

  const blocked = $derived(new Set(config.blocked_services));

  function toggle(id: string, on: boolean) {
    const next = new Set(config.blocked_services);
    if (on) next.add(id);
    else next.delete(id);
    config.blocked_services = [...next];
  }
</script>

<Card title="安全搜索" description="让 Google、Bing、DuckDuckGo、YouTube 等返回过滤后的“安全”结果，对整个网络生效。">
  <Switch bind:checked={config.safe_search} label="强制安全搜索" description="通过 DNS 把这些网站重定向到各自的安全搜索地址；浏览器里的“安全 DNS”（DoH）会绕过它，需要在路由器上一并限制。" />
</Card>

<Card title="屏蔽整个服务" description="一键屏蔽某个网站或应用的全部域名（含子域名）。你自己的“放行”规则优先于这里的屏蔽；暂停过滤期间不生效。">
  {#snippet actions()}
    <span class="badge" class:accent={blocked.size > 0}>已屏蔽 {blocked.size} 个</span>
  {/snippet}
  <div class="groups">
    {#each groups as group (group.name)}
      <section>
        <h3>{group.name}</h3>
        <div class="grid">
          {#each group.items as service (service.id)}
            <label class="service" class:on={blocked.has(service.id)} title={service.domains.join('\n')}>
              <input type="checkbox" checked={blocked.has(service.id)} onchange={(event) => toggle(service.id, event.currentTarget.checked)} />
              <span class="name">{service.name}</span>
              <span class="state">{blocked.has(service.id) ? '已屏蔽' : '允许'}</span>
            </label>
          {/each}
        </div>
      </section>
    {/each}
    {#if catalog.length === 0}<p class="muted">正在读取…</p>{/if}
  </div>
</Card>

<style>
  .groups { display: flex; flex-direction: column; gap: 18px; }
  h3 { margin-bottom: 8px; color: var(--muted); font-size: 12px; font-weight: 600; letter-spacing: 0.04em; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
  .service {
    display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 9px 12px; cursor: pointer;
    border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface);
    transition: border-color 0.12s, background 0.12s;
  }
  .service:hover { border-color: var(--line-strong); }
  .service.on { border-color: var(--danger); background: var(--danger-soft); }
  .service input { position: absolute; opacity: 0; pointer-events: none; }
  .service:focus-within { box-shadow: var(--focus); }
  .name { font-weight: 500; }
  .state { color: var(--muted); font-size: 12px; white-space: nowrap; }
  .service.on .state { color: var(--danger); font-weight: 600; }
</style>
