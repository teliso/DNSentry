<script lang="ts">
  /** A complete time zone picker: every IANA zone the browser knows, grouped by region, with its current UTC offset. */
  let { value = $bindable(''), emptyLabel }: { value?: string; emptyLabel: string } = $props();

  const FALLBACK = ['UTC', 'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Taipei', 'Asia/Tokyo', 'Asia/Seoul', 'Asia/Singapore', 'Asia/Kolkata', 'Asia/Dubai', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Sao_Paulo', 'Australia/Sydney', 'Pacific/Auckland'];

  function allZones(): string[] {
    try {
      const list = (Intl as unknown as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.('timeZone');
      if (list && list.length > 0) return list.includes('UTC') ? list : [...list, 'UTC'];
    } catch {
      /* older browsers */
    }
    return FALLBACK;
  }

  /** "UTC+8", "UTC-3:30" or "UTC" right now in that zone. */
  function offset(zone: string): string {
    try {
      const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'shortOffset' }).formatToParts(new Date()).find((item) => item.type === 'timeZoneName')?.value ?? '';
      return part.replace('GMT', 'UTC') || 'UTC';
    } catch {
      return '';
    }
  }

  const zones = allZones();
  const groups = (() => {
    const result = new Map<string, { id: string; label: string }[]>();
    for (const id of zones) {
      const region = id.includes('/') ? id.slice(0, id.indexOf('/')) : 'UTC';
      const list = result.get(region) ?? [];
      list.push({ id, label: `${id.replace(/_/g, ' ')} (${offset(id)})` });
      result.set(region, list);
    }
    return [...result.entries()].sort(([a], [b]) => a.localeCompare(b));
  })();

  const known = $derived(value === '' || zones.includes(value));
  const browser = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      return '';
    }
  })();
</script>

<div class="row">
  <select bind:value aria-label="Time zone">
    <option value="">{emptyLabel}</option>
    {#if !known}<option {value}>{value}</option>{/if}
    {#each groups as [region, items] (region)}
      <optgroup label={region}>
        {#each items as item (item.id)}<option value={item.id}>{item.label}</option>{/each}
      </optgroup>
    {/each}
  </select>
  {#if browser && value !== browser}
    <button class="btn sm" type="button" onclick={() => (value = browser)} title={browser}>{browser}</button>
  {/if}
</div>

<style>
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  select { flex: 1 1 280px; width: auto; min-width: 0; }
</style>
