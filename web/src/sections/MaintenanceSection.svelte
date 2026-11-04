<script lang="ts">
  import { ask } from '../lib/i18n/index.svelte';
  import Card from '../components/Card.svelte';
  import { api } from '../lib/api';
  import { formatRelative } from '../lib/format';
  import { settingLabel } from '../lib/settingLabels';
  import { store } from '../lib/store.svelte';
  import { toasts } from '../lib/toast.svelte';
  import type { ConfigVersion } from '../lib/types';

  const status = $derived(store.status);
  let versions = $state<ConfigVersion[]>([]);

  $effect(() => {
    store.configVersion;
    api
      .configHistory()
      .then((list) => (versions = list))
      .catch((cause) => toasts.error(cause instanceof Error ? cause.message : '读取配置历史失败'));
  });

  let picker: HTMLInputElement | undefined = $state();

  async function exportConfig() {
    try {
      await api.exportConfig();
    } catch (cause) {
      toasts.error(cause instanceof Error ? cause.message : '导出失败');
    }
  }

  async function importFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    if (file.size > 1 << 20) {
      toasts.error('配置文件太大（超过 1 MB）');
      return;
    }
    if (ask(`用“${file.name}”替换当前配置？当前配置会保留在历史中，可以再恢复回来。`)) await store.importConfig(await file.text());
  }

  function clearCache() {
    if (ask('清空 DNS 缓存？之后的查询会重新向上游请求，短时间内可能变慢。')) void store.clearCache();
  }

  function clearLogs() {
    if (ask('清空内存中的查询日志？这不能撤销（已保存到磁盘的日志不受影响）。')) void store.clearLogs();
  }

  function restore(version: ConfigVersion) {
    if (ask(`恢复到 ${new Date(version.time).toLocaleString('zh-CN', { hour12: false })} 保存的配置？当前配置会保留在历史中，可以再恢复回来。`)) {
      void store.restoreConfig(version.id);
    }
  }
</script>

<Card id="sec-maintenance" title="配置历史与维护" description="每次保存都会记录一个版本（最多 30 个），可以查看每次改了什么，并恢复到任意版本。">
  <div class="stack">
    {#if versions.length === 0}
      <p class="muted">还没有历史版本。</p>
    {:else}
      <div class="table-wrap bordered">
        <table class="data">
          <thead><tr><th>保存时间</th><th>改动</th><th></th></tr></thead>
          <tbody>
            {#each versions as version, index (version.id)}
              <tr>
                <td class="when">
                  <time datetime={version.time} title={new Date(version.time).toLocaleString('zh-CN', { hour12: false })}>{formatRelative(version.time)}</time>
                  {#if version.current}<span class="badge ok">当前</span>{/if}
                </td>
                <td>
                  {#if version.changes.length === 0}
                    <span class="muted">{index === versions.length - 1 ? '最早的记录' : '无可比较的改动'}</span>
                  {:else}
                    <span class="chips">
                      {#each version.changes as key (key)}<span class="badge" title={key}>{settingLabel(key)}</span>{/each}
                      {#if version.more_changes}<span class="muted">另有 {version.more_changes} 项</span>{/if}
                    </span>
                  {/if}
                </td>
                <td class="end">
                  <button class="btn sm" type="button" disabled={store.busy || version.current} onclick={() => restore(version)}>恢复</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    <div class="row">
      <div>
        <strong>导出 / 导入配置</strong>
        <p class="muted">导出的文件包含私钥等敏感信息，请妥善保管。导入会像在控制台保存一样校验并立即应用，并记入上面的历史，随时可以恢复。</p>
      </div>
      <div class="buttons">
        <button class="btn" type="button" onclick={exportConfig}>导出</button>
        <button class="btn" type="button" disabled={store.busy} onclick={() => picker?.click()}>导入…</button>
        <input bind:this={picker} type="file" accept=".yaml,.yml,text/yaml,application/yaml" hidden onchange={importFile} />
      </div>
    </div>
    <div class="cleanup">
      <strong>数据清理</strong>
      <div class="row">
        <div>
          <span>清空 DNS 缓存</span>
          <p class="muted">上游记录变更后需要立即生效时使用；缓存会随新查询重新建立。</p>
        </div>
        <button class="btn danger" type="button" disabled={store.busy} onclick={clearCache}>清空缓存</button>
      </div>
      <div class="row">
        <div>
          <span>清空内存中的查询日志</span>
          <p class="muted">清除日志页的最近记录和概览里据此统计的排行；累计数字、趋势图和已保存到磁盘的日志不受影响。</p>
        </div>
        <button class="btn danger" type="button" disabled={store.busy} onclick={clearLogs}>清空日志</button>
      </div>
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
  .bordered { border: 1px solid var(--line); border-radius: var(--radius-sm); max-height: 340px; overflow: auto; }
  .when { white-space: nowrap; }
  .when .badge { margin-left: 6px; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
  .end { text-align: right; }
  .cleanup { border-top: 1px solid var(--line); padding-top: 14px; display: flex; flex-direction: column; }
  .cleanup .row { border-top: 0; padding: 8px 0 0; }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 0; border-top: 1px solid var(--line); }
  .row p { font-size: 13px; }
  .buttons { display: flex; gap: 8px; flex: none; }
  .about { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px 16px; margin: 4px 0 0; }
  dt { color: var(--muted); font-size: 12px; }
  dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
</style>
