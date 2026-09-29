<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import ListEditor from '../components/ListEditor.svelte';
  import Switch from '../components/Switch.svelte';
  import { formatNumber } from '../lib/format';
  import { store } from '../lib/store.svelte';
  import type { Config } from '../lib/types';

  let { config }: { config: Config } = $props();
  const stats = $derived(store.status?.dnssec);
</script>

<Card title="DNSSEC" description="控制是否向上游请求 DNSSEC 数据，以及是否在本地验证签名链。">
  {#snippet actions()}
    <span class="badge" class:ok={config.dnssec_validate}>{config.dnssec_validate ? '本地验证开启' : '本地验证关闭'}</span>
  {/snippet}

  <div class="stack">
    <div class="form-grid">
      <Switch bind:checked={config.enable_dnssec} label="向上游请求 DNSSEC" description="为未携带 DO 标志的请求补充 DNSSEC 数据。" />
      <Switch bind:checked={config.dnssec_validate} label="启用本地验证" description="使用内置或自定义的信任锚校验签名链。" />
      <Switch bind:checked={config.dnssec_auto_update} label="自动更新根信任锚" description="经当前信任链验证后写入受控文件。" disabled={!config.dnssec_validate} />
    </div>

    {#if config.dnssec_validate}
      <div class="form-grid two">
        <Field label="受控信任锚文件" hint="与手工信任锚二选一；文件变更会自动验证并热重载。">
          <input class="mono" bind:value={config.dnssec_trust_anchor_file} placeholder="data/trust-anchors.txt" />
        </Field>
        <ListEditor label="手工 DNSKEY 信任锚" hint="留空使用内置 IANA 根信任锚" placeholder=". 172800 IN DNSKEY 257 3 8 …" code rows={3} bind:values={config.dnssec_trust_anchors} />
      </div>
    {/if}

    <p class="counters muted tabular">
      验证结果：Secure {formatNumber(stats?.secure ?? 0)} · Insecure {formatNumber(stats?.insecure ?? 0)} · Bogus {formatNumber(stats?.bogus ?? 0)} · Indeterminate {formatNumber(stats?.indeterminate ?? 0)}
    </p>
  </div>
</Card>

<style>
  .counters { font-size: 12px; }
</style>
