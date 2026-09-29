<script lang="ts">
  import { formatClock, formatNumber } from '../lib/format';
  import type { MetricPoint } from '../lib/types';

  let { points }: { points: MetricPoint[] } = $props();

  const W = 600;
  const H = 180;
  const PAD = 1;

  /** Rounds up to 1, 2 or 5 times a power of ten so gridlines land on whole, tidy values. */
  function niceStep(value: number): number {
    const magnitude = 10 ** Math.floor(Math.log10(Math.max(value, 1)));
    for (const step of [1, 2, 5, 10]) if (value <= step * magnitude) return step * magnitude;
    return 10 * magnitude;
  }

  const GRID_LINES = 4;
  const step = $derived(niceStep(Math.max(0, ...points.map((point) => point.queries)) / GRID_LINES));
  const top = $derived(step * GRID_LINES);
  const x = (index: number) => PAD + (points.length > 1 ? (index / (points.length - 1)) * (W - PAD * 2) : (W - PAD * 2) / 2);
  const y = (value: number) => H - PAD - (value / top) * (H - PAD * 2);
  const line = (field: 'queries' | 'blocked') => points.map((point, index) => `${x(index).toFixed(1)},${y(point[field]).toFixed(1)}`).join(' ');

  const totalLine = $derived(line('queries'));
  const blockedLine = $derived(line('blocked'));
  const area = $derived(points.length > 1 ? `${x(0)},${H - PAD} ${totalLine} ${x(points.length - 1)},${H - PAD}` : '');
  const ticks = $derived(Array.from({ length: GRID_LINES + 1 }, (_, index) => (GRID_LINES - index) * step));

  let hover = $state<number | null>(null);

  function onpointermove(event: PointerEvent) {
    if (points.length === 0) return;
    const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const ratio = Math.min(1, Math.max(0, (event.clientX - box.left) / box.width));
    hover = Math.round(ratio * (points.length - 1));
  }

  const active = $derived(hover === null ? null : points[hover] ?? null);
  const left = $derived(hover === null || points.length < 2 ? 0 : (x(hover) / W) * 100);
</script>

<figure>
  <div class="plot">
    <div class="yaxis tabular" aria-hidden="true">
      {#each ticks as tick (tick)}<span>{formatNumber(tick)}</span>{/each}
    </div>
    <div class="canvas" role="img" aria-label="最近 30 分钟的查询与拦截趋势" {onpointermove} onpointerleave={() => (hover = null)}>
      <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none">
        {#each ticks as tick (tick)}
          <line x1="0" x2={W} y1={y(tick)} y2={y(tick)} class="grid" />
        {/each}
        {#if points.length > 1}
          <polygon points={area} class="area" />
          <polyline points={totalLine} class="series total" />
          <polyline points={blockedLine} class="series blocked" />
        {/if}
      </svg>
      {#if active}
        <div class="cursor" style:left="{left}%"></div>
        <div class="tip tabular" style:left="{left}%" class:flip={left > 70}>
          <strong>{formatClock(active.time).slice(0, 5)}</strong>
          <span><i class="key total"></i>查询 {formatNumber(active.queries)}</span>
          <span><i class="key blocked"></i>拦截 {formatNumber(active.blocked)}</span>
        </div>
      {/if}
    </div>
    <div class="xaxis tabular" aria-hidden="true">
      {#if points.length > 0}
        <span>{formatClock(points[0].time).slice(0, 5)}</span>
        <span>{formatClock(points[Math.floor(points.length / 2)].time).slice(0, 5)}</span>
        <span>{formatClock(points[points.length - 1].time).slice(0, 5)}</span>
      {/if}
    </div>
  </div>
  <figcaption>
    <span><i class="key total"></i>全部查询</span>
    <span><i class="key blocked"></i>已拦截</span>
    <span class="muted">按分钟聚合 · 每 10 秒刷新</span>
  </figcaption>
</figure>

<style>
  figure { margin: 0; }
  .plot { display: grid; grid-template-columns: auto 1fr; gap: 10px; }
  .yaxis { display: flex; flex-direction: column; justify-content: space-between; height: 180px; text-align: right; color: var(--muted); font-size: 11px; line-height: 1; }
  .yaxis span { transform: translateY(-1px); }
  .canvas { position: relative; height: 180px; touch-action: pan-y; }
  svg { display: block; width: 100%; height: 100%; overflow: visible; }
  .grid { stroke: var(--line); stroke-width: 1; vector-effect: non-scaling-stroke; }
  .area { fill: var(--series-total); opacity: 0.09; }
  .series { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; vector-effect: non-scaling-stroke; }
  .series.total { stroke: var(--series-total); }
  .series.blocked { stroke: var(--series-blocked); }
  .cursor { position: absolute; top: 0; bottom: 0; width: 1px; background: var(--line-strong); pointer-events: none; }
  .tip {
    position: absolute; top: 4px; transform: translateX(10px);
    display: flex; flex-direction: column; gap: 1px; padding: 6px 10px; pointer-events: none;
    background: var(--surface); border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
    box-shadow: var(--shadow-pop); font-size: 12px; white-space: nowrap;
  }
  .tip.flip { transform: translateX(calc(-100% - 10px)); }
  .xaxis { grid-column: 2; display: flex; justify-content: space-between; margin-top: -4px; color: var(--muted); font-size: 11px; }
  figcaption { display: flex; flex-wrap: wrap; gap: 6px 18px; margin-top: 12px; font-size: 12px; }
  figcaption span { display: inline-flex; align-items: center; gap: 6px; }
  .key { display: inline-block; width: 10px; height: 3px; border-radius: 2px; }
  .key.total { background: var(--series-total); }
  .key.blocked { background: var(--series-blocked); }
</style>
