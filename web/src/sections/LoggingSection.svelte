<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card title="查询日志" description="控制台里的日志与仪表盘始终可用（保留最近 1000 条）。写入磁盘的日志会包含客户端 IP 与查询域名，请确认符合隐私要求。">
  {#snippet actions()}<span class="badge warn">重启后生效</span>{/snippet}
  <div class="stack">
    <Switch bind:checked={config.query_log_enabled} label="保存日志到磁盘" description="按天写入文件（与配置文件同目录），重启后仍可查看，并自动清理过期文件。" />
    {#if config.query_log_enabled}
      <Field label="保留天数" hint="1–365 天">
        <div class="unit narrow"><input type="number" min="1" max="365" bind:value={config.query_log_retention_days} /><span>天</span></div>
      </Field>
    {/if}
  </div>
</Card>
