<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';

  type Tone = 'accent' | 'danger' | 'ok' | 'neutral';
  let {
    label,
    value,
    sub,
    icon,
    tone = 'accent',
    spark = []
  }: { label: string; value: string; sub?: string; icon: IconName; tone?: Tone; spark?: number[] } = $props();

  const W = 100;
  const H = 32;
  const points = $derived.by(() => {
    if (spark.length < 2) return '';
    const max = Math.max(1, ...spark);
    return spark.map((v, i) => `${((i / (spark.length - 1)) * W).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`).join(' ');
  });
</script>

<article class="stat {tone}">
  <header>
    <span class="chip"><Icon name={icon} size={16} /></span>
    <span class="label">{label}</span>
  </header>
  <strong class="tabular">{value}</strong>
  {#if sub}<small>{sub}</small>{/if}
  {#if points}
    <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true">
      <polygon points="0,{H} {points} {W},{H}" class="fill" />
      <polyline {points} class="line" vector-effect="non-scaling-stroke" />
    </svg>
  {/if}
</article>

<style>
  .stat {
    --c: var(--series-total);
    position: relative; overflow: hidden; display: flex; flex-direction: column; gap: 2px; min-height: 124px;
    padding: 16px 18px 14px;
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  }
  .stat.danger { --c: var(--series-blocked); }
  .stat.ok { --c: var(--ok); }
  .stat.neutral { --c: var(--muted); }
  header { display: flex; align-items: center; gap: 9px; color: var(--muted); font-size: 13px; position: relative; z-index: 1; }
  .chip { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; color: var(--c); background: color-mix(in srgb, var(--c) 14%, transparent); }
  strong { position: relative; z-index: 1; margin-top: 4px; font-size: 28px; line-height: 1.2; letter-spacing: -0.02em; font-weight: 650; }
  small { position: relative; z-index: 1; color: var(--muted); }
  svg { position: absolute; left: 0; right: 0; bottom: 0; width: 100%; height: 44px; }
  .fill { fill: color-mix(in srgb, var(--c) 12%, transparent); }
  .line { fill: none; stroke: var(--c); stroke-width: 1.5; stroke-linejoin: round; opacity: 0.55; }
</style>
