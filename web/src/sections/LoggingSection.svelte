<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card id="sec-logging" title="查询日志" description="内存日志与仪表盘始终可用。持久化日志会包含客户端 IP 与查询域名，请确认符合隐私与合规要求。">
  {#snippet actions()}<span class="badge warn">重启后生效</span>{/snippet}
  <div class="stack">
    <Switch bind:checked={config.query_log_enabled} label="启用 JSONL 持久化" description="按日期异步写入日志文件，并自动清理过期文件。" />
    <div class="form-grid">
      <Field label="内存日志条数" hint="API 保留的最近记录数">
        <input type="number" min="1" bind:value={config.query_log_size} />
      </Field>
      {#if config.query_log_enabled}
        <Field label="文件前缀" hint="例如 data/querylog-2026-09-07.jsonl">
          <input class="mono" bind:value={config.query_log_file} placeholder="data/querylog" />
        </Field>
        <Field label="保留天数" hint="1–365 天">
          <div class="unit"><input type="number" min="1" max="365" bind:value={config.query_log_retention_days} /><span>天</span></div>
        </Field>
      {/if}
    </div>
  </div>
</Card>
