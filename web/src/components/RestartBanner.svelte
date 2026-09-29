<script lang="ts">
  import Icon from './Icon.svelte';
  import { store } from '../lib/store.svelte';
</script>

{#if store.status?.restart_required}
  <div class="banner" role="status">
    <Icon name="alert" />
    <span>已保存的配置中有监听地址、查询日志或加密 DNS 的改动，需要<strong>重启服务</strong>后生效；其余设置已即时应用。</span>
  </div>
{/if}

<style>
  .banner {
    display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px;
    background: var(--warn-soft); color: var(--warn); border-radius: var(--radius-sm);
  }
  .banner :global(svg) { margin-top: 3px; }
  span { color: var(--ink-2); }
  strong { color: var(--warn); }
</style>
