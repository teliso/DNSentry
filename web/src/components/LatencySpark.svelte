<script lang="ts">
  import { formatDuration } from '../lib/format';
  import type { HealthPoint } from '../lib/types';

  /** Latency over the last 30 minutes as a sparkline; minutes with failures get a marker. */
  let { points, width = 120, height = 28 }: { points: HealthPoint[]; width?: number; height?: number } = $props();

  const requests = $derived(points.reduce((sum, point) => sum + point.requests, 0));
  const failures = $derived(points.reduce((sum, point) => sum + point.failures, 0));
  const successes = $derived(requests - failures);
  const average = $derived(
    successes > 0 ? points.reduce((sum, point) => sum + point.average_latency_ms * (point.requests - point.failures), 0) / successes : 0
  );
  const peak = $derived(Math.max(1, ...points.map((point) => point.average_latency_ms)));

  const x = (index: number) => (points.length > 1 ? (index / (points.length - 1)) * (width - 4) + 2 : width / 2);
  const y = (value: number) => height - 3 - (value / peak) * (height - 6);

  /** Consecutive minutes with successful requests form one line segment. */
  const segments = $derived.by(() => {
    const result: string[] = [];
    let current: string[] = [];
    points.forEach((point, index) => {
      if (point.requests - point.failures > 0) current.push(`${x(index).toFixed(1)},${y(point.average_latency_ms).toFixed(1)}`);
      else if (current.length > 0) {
        result.push(current.join(' '));
        current = [];
      }
    });
    if (current.length > 0) result.push(current.join(' '));
    return result;
  });
  const lonely = $derived(points.flatMap((point, index) => (point.requests - point.failures > 0 && !hasNeighbour(index) ? [{ cx: x(index), cy: y(point.average_latency_ms) }] : [])));

  function hasNeighbour(index: number): boolean {
    const active = (i: number) => i >= 0 && i < points.length && points[i].requests - points[i].failures > 0;
    return active(index - 1) || active(index + 1);
  }

  const summary = $derived(
    requests === 0 ? '最近 30 分钟没有请求' : `平均 ${formatDuration(average)} · 峰值 ${peak} ms · 失败 ${failures}/${requests}`
  );
</script>

<span class="spark" title={summary}>
  <svg {width} {height} viewBox="0 0 {width} {height}" role="img" aria-label="最近 30 分钟延迟：{summary}">
    {#each segments as segment (segment)}
      {#if segment.includes(' ')}<polyline points={segment} class="line" />{/if}
    {/each}
    {#each lonely as dot (dot.cx)}<circle cx={dot.cx} cy={dot.cy} r="1.6" class="dot" />{/each}
    {#each points as point, index (point.time)}
      {#if point.failures > 0}<line x1={x(index)} x2={x(index)} y1={height - 1} y2={height - 7} class="fail" />{/if}
    {/each}
  </svg>
  <span class="text tabular">{requests === 0 ? '—' : formatDuration(average)}{failures > 0 ? ` · ${Math.round((failures / requests) * 100)}% 失败` : ''}</span>
</span>

<style>
  .spark { display: inline-flex; align-items: center; gap: 8px; }
  svg { display: block; overflow: visible; }
  .line { fill: none; stroke: var(--series-total); stroke-width: 1.5; stroke-linejoin: round; stroke-linecap: round; }
  .dot { fill: var(--series-total); }
  .fail { stroke: var(--danger); stroke-width: 2; stroke-linecap: round; }
  .text { color: var(--muted); font-size: 12px; min-width: 64px; text-align: right; }
</style>
