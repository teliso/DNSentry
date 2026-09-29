<script lang="ts">
  let { label, value, sub, tone = 'accent' }: { label: string; value: string; sub?: string; tone?: 'accent' | 'danger' | 'ok' | 'neutral' } = $props();
</script>

<article class="stat">
  <div class="label"><span class="dot {tone}"></span>{label}</div>
  <strong class="tabular">{value}</strong>
  {#if sub}<small>{sub}</small>{/if}
</article>

<style>
  .stat {
    display: flex; flex-direction: column; gap: 2px; padding: 16px 18px;
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  }
  .label { display: flex; align-items: center; gap: 7px; color: var(--muted); font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
  .dot.accent { background: var(--series-total); }
  .dot.danger { background: var(--series-blocked); }
  .dot.ok { background: var(--ok); }
  .dot.neutral { background: var(--muted); }
  strong { font-size: 26px; line-height: 1.25; letter-spacing: -0.02em; font-weight: 650; }
  small { color: var(--muted); }
</style>
