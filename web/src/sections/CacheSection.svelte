<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatBytes, formatNumber, formatPercent } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
  const cache = $derived(store.status?.cache);

  const MB = 1 << 20;
  // The config stores bytes; the form edits megabytes.
  const megabytes = {
    get value() {
      return Math.max(1, Math.round(config.cache_size / MB));
    },
    set value(next: number) {
      config.cache_size = Math.max(1, Math.round(Number(next) || 1)) * MB;
    }
  };
</script>

<Card title="DNS 缓存" description="缓存解析结果，快速应答重复查询。热门条目会在过期前自动在后台刷新。">
  {#snippet actions()}
    <span class="muted tabular stat">
      {formatNumber(cache?.entries ?? 0)} 条 · {formatBytes(cache?.used_bytes ?? 0)} · 命中率 {formatPercent(cache?.hit_rate ?? 0)}
    </span>
    <button class="btn sm" type="button" disabled={store.busy} onclick={() => store.clearCache()}>清空缓存</button>
  {/snippet}

  <div class="stack">
    <div class="form-grid two">
      <Switch bind:checked={config.cache_enabled} label="启用缓存" description="关闭后所有请求直接转发到上游。" />
      <Switch bind:checked={config.cache_optimistic} label="乐观缓存" description="先返回刚过期的响应，再在后台刷新，网络慢时体感更快。" disabled={!config.cache_enabled} />
    </div>
    <Field label="缓存大小" hint="超出后淘汰最久未使用的条目">
      <div class="unit narrow"><input type="number" min="1" bind:value={megabytes.value} disabled={!config.cache_enabled} /><span>MB</span></div>
    </Field>
  </div>
</Card>

<style>
  .stat { font-size: 12px; }
</style>
