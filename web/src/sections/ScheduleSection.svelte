<script lang="ts">
  import Card from '../components/Card.svelte';
  import Field from '../components/Field.svelte';
  import Icon from '../components/Icon.svelte';
  import Switch from '../components/Switch.svelte';
  import { api } from '../lib/api';
  import { store } from '../lib/store.svelte';
  import type { Config, ScheduleRule, ServiceInfo } from '../lib/types';

  let { config }: { config: Config } = $props();
  const rules = $derived(config.schedule.rules);
  let catalog = $state<ServiceInfo[]>([]);
  api.services().then((list) => (catalog = list)).catch(() => {});

  // Monday first; the values are Go/JS weekday numbers (0 = Sunday).
  const DAYS = [
    { value: 1, label: '一' }, { value: 2, label: '二' }, { value: 3, label: '三' }, { value: 4, label: '四' },
    { value: 5, label: '五' }, { value: 6, label: '六' }, { value: 0, label: '日' }
  ];
  const ZONES = ['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Taipei', 'Asia/Tokyo', 'Asia/Singapore', 'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles', 'UTC'];

  function add() {
    config.schedule.rules = [...rules, { name: '', enabled: true, days: [], start: '22:00', end: '07:00', services: [], safe_search: false }];
  }
  const remove = (index: number) => (config.schedule.rules = rules.filter((_, current) => current !== index));

  function toggleDay(rule: ScheduleRule, day: number) {
    rule.days = rule.days.includes(day) ? rule.days.filter((value) => value !== day) : [...rule.days, day];
  }
  function toggleService(rule: ScheduleRule, id: string) {
    rule.services = rule.services.includes(id) ? rule.services.filter((value) => value !== id) : [...rule.services, id];
  }

  /** "22:00 – 07:00（次日）" for the summary line. */
  const spans = (rule: ScheduleRule) => (rule.start === rule.end ? '全天' : `${rule.start} – ${rule.end}${rule.end < rule.start ? '（次日）' : ''}`);

  const now = $derived.by(() => {
    if (!store.status?.server_time) return '';
    try {
      return new Date(store.status.server_time).toLocaleString('zh-CN', { hour12: false, timeZone: config.schedule.timezone.trim() || undefined });
    } catch {
      return '';
    }
  });
  const active = $derived(new Set(store.status?.active_schedules ?? []));
</script>

<Card title="计划任务" description="按周和时间段自动生效：在窗口内屏蔽指定的服务、并可强制安全搜索，窗口结束后自动恢复。适合“晚上不能玩游戏”“上课时间屏蔽视频”这类需求，对整个网络生效。">
  {#snippet actions()}
    {#if active.size > 0}<span class="badge warn">生效中：{[...active].join('、')}</span>{/if}
  {/snippet}

  <div class="stack">
    <div class="tz">
      <Field label="时区" hint={now ? `按这个时区计时，现在是 ${now}` : '留空 = 服务器的本地时间（容器里通常是 UTC）'}>
        <input list="zones" bind:value={config.schedule.timezone} placeholder="留空 = 服务器本地时间，例如 Asia/Shanghai" spellcheck="false" autocapitalize="off" />
        <datalist id="zones">{#each ZONES as zone (zone)}<option value={zone}></option>{/each}</datalist>
      </Field>
    </div>

    {#if rules.length === 0}
      <p class="muted">还没有计划。添加一个计划，比如“工作日 22:00 到次日 07:00 屏蔽游戏”。</p>
    {/if}

    {#each rules as rule, index (index)}
      <div class="rule" class:off={!rule.enabled}>
        <div class="head">
          <input class="name" bind:value={rule.name} placeholder="名称，例如 睡觉时间" maxlength="64" aria-label="名称" />
          <Switch bind:checked={rule.enabled} label="启用" />
          <button class="btn sm danger icon" type="button" aria-label="删除计划" onclick={() => remove(index)}><Icon name="trash" /></button>
        </div>

        <div class="when">
          <div class="days" role="group" aria-label="星期">
            {#each DAYS as day (day.value)}
              <button type="button" class="day" class:on={rule.days.length === 0 || rule.days.includes(day.value)} aria-pressed={rule.days.length === 0 || rule.days.includes(day.value)} onclick={() => toggleDay(rule, day.value)}>{day.label}</button>
            {/each}
          </div>
          <div class="times">
            <input type="time" bind:value={rule.start} aria-label="开始时间" />
            <span>至</span>
            <input type="time" bind:value={rule.end} aria-label="结束时间" />
          </div>
        </div>
        <p class="muted small">
          {rule.days.length === 0 || rule.days.length === 7 ? '每天' : '所选的星期'}，{spans(rule)}。{rule.end < rule.start ? '结束时间早于开始时间时，窗口跨过午夜，属于它开始的那一天。' : rule.start === rule.end ? '开始和结束相同表示全天。' : ''}
        </p>

        <div class="svc">
          <span class="muted small">屏蔽的服务</span>
          <div class="chips">
            {#each catalog as service (service.id)}
              <button type="button" class="chip" class:on={rule.services.includes(service.id)} aria-pressed={rule.services.includes(service.id)} onclick={() => toggleService(rule, service.id)}>{service.name}</button>
            {/each}
          </div>
        </div>
        <Switch bind:checked={rule.safe_search} label="同时强制安全搜索" />
      </div>
    {/each}

    <div><button class="btn" type="button" disabled={rules.length >= 16} onclick={add}><Icon name="plus" />添加计划</button></div>
    <p class="muted small">你自己的“放行”规则优先于计划；暂停过滤期间计划里的屏蔽也不生效。窗口开关的瞬间，缓存里按旧状态保存的安全搜索结果会被清空。</p>
  </div>
</Card>

<style>
  .tz { max-width: 460px; }
  .rule { display: flex; flex-direction: column; gap: 10px; padding: 14px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
  .rule.off { opacity: 0.65; }
  .head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .name { flex: 1 1 200px; }
  .when { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
  .days { display: inline-flex; gap: 4px; }
  .day { width: 32px; height: 32px; border-radius: 50%; border: 1px solid var(--line-strong); background: var(--surface); cursor: pointer; font-weight: 500; }
  .day.on { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
  .times { display: inline-flex; gap: 8px; align-items: center; }
  .times input { width: 120px; }
  .svc { display: flex; flex-direction: column; gap: 6px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { padding: 3px 11px; border-radius: 999px; border: 1px solid var(--line-strong); background: var(--surface); cursor: pointer; font-size: 13px; color: var(--ink-2); }
  .chip:hover { border-color: var(--accent); }
  .chip.on { background: var(--danger-soft); border-color: var(--danger); color: var(--danger); font-weight: 600; }
  .small { font-size: 12px; }
</style>
