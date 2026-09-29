<script lang="ts">
  import Card from '../components/Card.svelte';
  import { store } from '../lib/store.svelte';

  const status = $derived(store.status);

  function restore() {
    if (confirm('用上一次保存之前的配置覆盖当前配置？当前配置会成为新的备份，可以再次恢复回来。')) void store.restoreConfig();
  }
</script>

<Card id="sec-maintenance" title="备份与维护" description="每次保存配置前，旧配置会备份为 config.yaml.bak。">
  <div class="stack">
    <div class="row">
      <div>
        <strong>恢复上一次配置</strong>
        <p class="muted">撤销最近一次保存。监听、日志或加密相关的改动需要重启后生效。</p>
      </div>
      <button class="btn" type="button" disabled={store.busy} onclick={restore}>恢复</button>
    </div>
    <div class="row">
      <div>
        <strong>清空 DNS 缓存</strong>
        <p class="muted">上游记录变更后需要立即生效时使用。</p>
      </div>
      <button class="btn" type="button" disabled={store.busy} onclick={() => store.clearCache()}>清空</button>
    </div>
    <dl class="about">
      <div><dt>版本</dt><dd class="mono">{status?.version ?? '—'}</dd></div>
      <div><dt>配置文件</dt><dd class="mono">{status?.config_path ?? '—'}</dd></div>
      <div><dt>本地规则文件</dt><dd class="mono">{status?.rules_file ?? '—'}</dd></div>
      <div><dt>指标</dt><dd><a href="/api/metrics" target="_blank" rel="noreferrer">/api/metrics</a>（Prometheus）</dd></div>
    </dl>
  </div>
</Card>

<style>
  .row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
  .row p { font-size: 13px; }
  .about { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px 16px; margin: 4px 0 0; }
  dt { color: var(--muted); font-size: 12px; }
  dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
</style>
