<script lang="ts">
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Field from '../components/Field.svelte';
  import Icon from '../components/Icon.svelte';
  import LatencySpark from '../components/LatencySpark.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();

  const health = $derived(store.status?.upstream_routes ?? []);

  function add() {
    config.upstream_routes.push({ name: '', domains: [], upstreams: [] });
  }
</script>

<Card
  id="sec-routes"
  title="域名分流"
  description="让指定域名（含子域名）使用专属上游，例如内网域名交给路由器或公司 DNS。分流的域名只会发给它的专属上游，失败时不会回退到公网上游，避免泄露内部域名。"
>
  {#snippet actions()}
    <button class="btn sm" type="button" onclick={add}><Icon name="plus" />添加分流</button>
  {/snippet}

  {#if config.upstream_routes.length === 0}
    <EmptyState title="暂无分流规则">例如把 <code>corp.example.com</code> 指向 <code>10.0.0.1:53</code>；也可以用于把 <code>10.in-addr.arpa</code> 之类的私网反向区交给内网 DNS。</EmptyState>
  {:else}
    <ul class="routes">
      {#each config.upstream_routes as route, index (index)}
        {@const status = health[index]}
        <li>
          <div class="head">
            <Field label="名称（可选）"><input maxlength="64" placeholder="公司内网" bind:value={route.name} /></Field>
            <button class="btn ghost sm danger" type="button" aria-label="删除分流 {index + 1}" onclick={() => config.upstream_routes.splice(index, 1)}><Icon name="trash" />删除</button>
          </div>
          <div class="form-grid two">
            <ListEditor label="域名" hint="含所有子域名" placeholder="corp.example.com&#10;10.in-addr.arpa" code rows={3} maxItems={64} bind:values={route.domains} />
            <ListEditor label="专属上游" hint="格式同上游服务器，最多 8 个" placeholder="10.0.0.1:53" code rows={3} maxItems={8} bind:values={route.upstreams} />
          </div>
          {#if status && status.upstreams.length > 0}
            <ul class="health">
              {#each status.upstreams as upstream (upstream.address)}
                <li>
                  <span class="dot" class:bad={!upstream.healthy} title={upstream.healthy ? '正常' : `连续失败 ${upstream.failures} 次`}></span>
                  <span class="mono addr">{upstream.address}</span>
                  <LatencySpark points={upstream.history ?? []} />
                </li>
              {/each}
            </ul>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</Card>

<style>
  .routes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 16px; }
  .routes li { display: flex; flex-direction: column; gap: 12px; padding: 14px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .head { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; }
  .head :global(.field) { flex: 0 1 360px; }
  .health { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
  .health li { display: flex; align-items: center; gap: 8px; }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.bad { background: var(--danger); }
  .addr { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
</style>
