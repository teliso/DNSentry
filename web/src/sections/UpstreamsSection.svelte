<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import Modal from '../components/Modal.svelte';
  import { cleanList } from '../lib/config';
  import { store } from '../lib/store.svelte';
  import type { Config, UpstreamMode, UpstreamTest } from '../lib/types';

  let { config }: { config: Config } = $props();

  const MODES: { value: UpstreamMode; title: string; text: string }[] = [
    { value: 'load_balance', title: '负载均衡', text: '按健康状态轮转，额外流量最少，适合常规部署。' },
    { value: 'parallel', title: '并行请求', text: '同时询问多个上游，采用首个有效响应；更快容错，但请求量成倍增加。' }
  ];

  let results = $state<UpstreamTest[] | null>(null);

  async function test() {
    results = await store.testUpstreams(cleanList(config.upstreams));
  }
</script>

<Card id="sec-upstreams" title="上游服务器" description="主上游负责常规请求；备用上游只在主上游无可用响应、超时或返回 SERVFAIL/REFUSED 时接管。">
  {#snippet actions()}
    <button class="btn" type="button" disabled={store.busy || cleanList(config.upstreams).length === 0} onclick={test}>测试上游</button>
  {/snippet}

  <div class="stack">
    <p class="protocols">
      <span class="badge mono">1.1.1.1:53</span>
      <span class="badge mono">tls://host:853</span>
      <span class="badge mono">https://host/dns-query</span>
      <span class="badge mono">h3://host/dns-query</span>
      <span class="badge mono">quic://host:853</span>
      <span class="badge mono">sdns://…</span>
    </p>
    <div class="editors">
      <ListEditor label="主上游 DNS" hint="按顺序填写，最多 32 个" placeholder="1.1.1.1:53&#10;https://dns.example/dns-query" maxItems={32} code rows={5} bind:values={config.upstreams} />
      <ListEditor label="备用 DNS" hint="主上游不可用时使用" placeholder="tls://backup.example:853" maxItems={32} code rows={5} bind:values={config.fallback_upstreams} />
      <ListEditor label="Bootstrap DNS" hint="仅用于解析加密上游的域名" placeholder="1.1.1.1:53" maxItems={16} code rows={5} bind:values={config.bootstrap_dns} />
    </div>

    <hr class="divider" />

    <div class="mode-group">
      <span class="group-label" id="mode-label">请求分发策略</span>
      <div class="modes" role="radiogroup" aria-labelledby="mode-label">
        {#each MODES as mode (mode.value)}
          <label class="mode" class:selected={config.upstream_mode === mode.value}>
            <input type="radio" name="upstream_mode" value={mode.value} bind:group={config.upstream_mode} />
            <strong>{mode.title}</strong>
            <small>{mode.text}</small>
          </label>
        {/each}
      </div>
    </div>

    <div class="form-grid">
      <Field label="单个上游超时" hint="连接与查询的最大等待时间">
        <div class="unit"><input type="number" min="1" bind:value={config.upstream_timeout_seconds} /><span>秒</span></div>
      </Field>
    </div>
  </div>
</Card>

{#if results}
  <Modal title="上游测试结果" onclose={() => (results = null)}>
    <ul class="results">
      {#each results as result (result.address)}
        <li>
          <span class="dot" class:bad={!result.success}></span>
          <span class="addr mono" title={result.address}>{result.address}</span>
          <span class="badge">{result.protocol}</span>
          <span class="tabular" class:bad-text={!result.success}>{result.success ? `${result.latency_ms} ms` : result.error}</span>
        </li>
      {/each}
    </ul>
    {#snippet footer()}
      <button class="btn primary" type="button" onclick={() => (results = null)}>完成</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .protocols { display: flex; flex-wrap: wrap; gap: 6px; }
  /* Three editors of the same height side by side. */
  .editors { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
  .mode-group { display: flex; flex-direction: column; gap: 8px; }
  .group-label { font-weight: 500; font-size: 13px; }
  .modes { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
  .mode {
    position: relative; display: flex; flex-direction: column; gap: 3px; padding: 12px 14px; cursor: pointer;
    border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface);
  }
  .mode:hover { border-color: var(--muted); }
  .mode.selected { border-color: var(--accent); background: var(--accent-soft); box-shadow: inset 0 0 0 1px var(--accent); }
  .mode input { position: absolute; opacity: 0; pointer-events: none; }
  .mode:has(input:focus-visible) { box-shadow: var(--focus); }
  .mode small { color: var(--muted); }

  .results { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .results li { display: flex; align-items: center; gap: 10px; }
  .addr { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.bad { background: var(--danger); }
  .bad-text { color: var(--danger); max-width: 40%; overflow-wrap: anywhere; font-size: 12px; }
  @media (max-width: 1000px) { .editors { grid-template-columns: 1fr; } }
  @media (max-width: 860px) { .modes { grid-template-columns: 1fr; } }
</style>
