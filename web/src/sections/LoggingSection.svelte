<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
</script>

<Card id="sec-logging" title="查询日志" description="记录每次 DNS 查询（域名、客户端、结果），用于“日志”页。关闭后完全不记录，仪表盘的计数与趋势仍然可用。持久化日志会包含客户端 IP 与查询域名，请确认符合隐私与合规要求。">
  <div class="stack">
    <Switch checked={!config.query_log_disabled} onchange={(value) => (config.query_log_disabled = !value)} label="记录查询日志" description="关闭后既不保存在内存，也不写入磁盘；已有记录可在“设置 → 维护”里清空。立即生效。" />
    {#if !config.query_log_disabled}
      <Switch bind:checked={config.query_log_enabled} label="保存到磁盘（JSONL）" description="按日期异步写入日志文件，并自动清理过期文件。重启后生效。" />
      <div class="form-grid">
        <Field label="内存日志条数" hint="日志页显示的最近记录数；重启后生效">
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
    {/if}
  </div>
</Card>

<Card id="sec-program-log" title="程序日志" description="程序自己的运行信息（启动、规则更新、上游故障、配置变更等），显示在“日志 → 程序日志”，同时输出到标准错误。">
  <div class="form-grid">
    <Field label="记录级别" hint="选择“关闭”则不记录也不输出；立即生效">
      <select bind:value={config.program_log_level}>
        <option value="">跟随启动参数（-log-level）</option>
        <option value="debug">调试</option>
        <option value="info">信息</option>
        <option value="warn">警告</option>
        <option value="error">仅错误</option>
        <option value="off">关闭</option>
      </select>
    </Field>
  </div>
</Card>
