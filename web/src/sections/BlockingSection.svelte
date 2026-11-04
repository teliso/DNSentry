<script lang="ts">
  import Card from '../components/Card.svelte';
  import type { BlockingMode, Config } from '../lib/types';

  let { config }: { config: Config } = $props();

  const MODES: { value: BlockingMode; title: string; text: string }[] = [
    { value: 'nxdomain', title: 'NXDOMAIN', text: '告诉客户端域名不存在，最干净，推荐。' },
    { value: 'null_ip', title: '空 IP', text: '返回 0.0.0.0 或 ::，客户端会立刻连接失败。' },
    { value: 'refused', title: 'REFUSED', text: '拒绝查询，部分客户端会改问别的 DNS 服务器。' }
  ];
</script>

<Card title="拦截响应" description="命中过滤规则时返回给客户端的内容。">
  <div class="modes" role="radiogroup" aria-label="拦截响应方式">
    {#each MODES as mode (mode.value)}
      <label class="mode" class:selected={config.blocking_mode === mode.value}>
        <input type="radio" name="blocking_mode" value={mode.value} bind:group={config.blocking_mode} />
        <strong>{mode.title}</strong>
        <small>{mode.text}</small>
      </label>
    {/each}
  </div>
</Card>

<style>
  .modes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  .mode {
    display: flex; flex-direction: column; gap: 2px; padding: 12px 14px; cursor: pointer;
    border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface);
    transition: border-color 0.12s, background 0.12s;
  }
  .mode:hover { border-color: var(--line-strong); }
  .mode.selected { border-color: var(--accent); background: var(--accent-soft); }
  .mode input { position: absolute; opacity: 0; pointer-events: none; }
  .mode:focus-within { box-shadow: var(--focus); }
  small { color: var(--muted); }
  @media (max-width: 720px) { .modes { grid-template-columns: 1fr; } }
</style>
