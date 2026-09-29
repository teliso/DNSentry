<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatBytes, formatNumber, formatPercent } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
  const cache = $derived(store.status?.cache);
</script>

<Card id="sec-cache" title="DNS 缓存" description="按字节容量运行的分片 LRU 缓存，支持负缓存与过期后台刷新。">
  {#snippet actions()}
    <span class="muted tabular stat">
      {formatNumber(cache?.entries ?? 0)} 条 · {formatBytes(cache?.used_bytes ?? 0)} · 命中率 {formatPercent(cache?.hit_rate ?? 0)}
    </span>
    <button class="btn sm" type="button" disabled={store.busy} onclick={() => store.clearCache()}>清空缓存</button>
  {/snippet}

  <div class="stack">
    <div class="form-grid three">
      <Switch bind:checked={config.cache_enabled} label="启用缓存" description="关闭后所有请求直接转发到上游。" />
      <Switch bind:checked={config.cache_prefetch} label="预取热门条目" description="被反复访问的条目在 TTL 最后 20% 时于后台刷新，避免过期。" disabled={!config.cache_enabled} />
      <Switch bind:checked={config.cache_optimistic} label="乐观缓存" description="先返回过期响应，再在后台刷新。" disabled={!config.cache_enabled} />
    </div>
    <div class="form-grid">
      <Field label="缓存大小" hint="字节，建议至少 4194304（4 MB）">
        <input type="number" min="0" bind:value={config.cache_size} disabled={!config.cache_enabled} />
      </Field>
      <Field label="TTL 下限" hint="秒，0 表示不限制">
        <input type="number" min="0" bind:value={config.cache_ttl_min} disabled={!config.cache_enabled} />
      </Field>
      <Field label="TTL 上限" hint="秒，0 表示不限制">
        <input type="number" min="0" bind:value={config.cache_ttl_max} disabled={!config.cache_enabled} />
      </Field>
      {#if config.cache_optimistic}
        <Field label="乐观应答 TTL" hint="返回过期响应时的 TTL（秒）">
          <input type="number" min="0" bind:value={config.cache_optimistic_answer_ttl} />
        </Field>
        <Field label="乐观缓存最大寿命" hint="过期后继续保留旧响应的秒数">
          <input type="number" min="0" bind:value={config.cache_optimistic_max_age} />
        </Field>
      {/if}
    </div>
  </div>
</Card>

<style>
  .stat { font-size: 12px; }
</style>
