<script lang="ts">
  import { onMount } from 'svelte';
  import { writable } from 'svelte/store';
  import ListEditor from './components/ListEditor.svelte';

  type RuleAction = 'block' | 'allow';
  type Rule = { domain: string; action: RuleAction; ip?: string };
  type MetricPoint = { time: string; queries: number; blocked: number };
  type UpstreamHealth = { address: string; healthy: boolean; failures: number; latency_ms: number; last_success?: string; last_failure?: string };
  type UpstreamTest = { address: string; protocol: string; success: boolean; latency_ms: number; error?: string };
  type RuleSource = { url: string; enabled: boolean; interval_minutes: number; last_updated?: string; last_error?: string; rule_count: number };
  type CacheStats = { entries: number; used_bytes: number; max_bytes: number; hits: number; misses: number; stale_hits: number; evictions: number; bypasses: number; refresh_success: number; refresh_failure: number; hit_rate: number };
  type DNSSECStats = { secure: number; insecure: number; bogus: number; indeterminate: number };
  type DNSCryptStatus = { enabled: boolean; running: boolean; listen: string; listens: string[]; provider_name: string; stamp?: string; udp: boolean; tcp: boolean };
  type Dashboard = {
    average_processing_ms: number;
    client_ips: { name: string; count: number }[];
    domains: { name: string; count: number }[];
    blocked_domains: { name: string; count: number }[];
    upstreams: { address: string; count: number; average_duration_ms: number }[];
  };
  type Status = {
    dns_listen: string;
    dns_listens: string[];
    http_listen: string;
    upstreams: string[];
    total_queries: number;
    blocked_queries: number;
    rules: number;
    cache: CacheStats;
    dnssec: DNSSECStats;
    dnscrypt: DNSCryptStatus;
    dashboard: Dashboard;
    series: MetricPoint[];
    upstream_health: UpstreamHealth[];
    rule_sources: RuleSource[];
  };
  type LogEntry = {
    time: string;
    domain: string;
    type: string;
    action: string;
    upstream?: string;
    duration_ms: number;
  };
  type DNSCryptConfig = { enabled: boolean; listen: string; listens: string[]; provider_name: string; private_key: string; resolver_secret: string; certificate_ttl_hours: number };
  type DNSAccessConfig = { allowed_clients: string[]; denied_clients: string[]; client_rate_limit_qps: number; max_concurrent_queries: number; rebinding_protection: boolean; rebinding_allow_domains: string[] };
  type LocalRecord = { domain: string; type: string; value: string; ttl: number };
  type EncryptionConfig = { enabled: boolean; certificate: string; private_key: string; certificate_pem: string; private_key_pem: string; dot_listen: string; dot_listens: string[]; doh_listen: string; doh_listens: string[]; doh3_listen: string; doh3_listens: string[]; doq_listen: string; doq_listens: string[]; dnscrypt: DNSCryptConfig };
  class APIError extends Error {
    status: number;
    data: any;

    constructor(status: number, data: any) {
      super(data?.error || '请求失败');
      this.name = 'APIError';
      this.status = status;
      this.data = data;
    }
  }

  type Config = {
    dns_listen: string;
    dns_listens: string[];
    http_listen: string;
    upstreams: string[];
    fallback_upstreams: string[];
    upstream_mode: string;
    local_records: LocalRecord[];
    access: DNSAccessConfig;
    bootstrap_dns: string[];
    upstream_timeout_seconds: number;
    blocking_mode: string;
    blocking_ipv4: string;
    blocking_ipv6: string;
    blocked_response_ttl: number;
    enable_dnssec: boolean;
    dnssec_validate: boolean;
    dnssec_trust_anchors: string[];
    dnssec_trust_anchor_file: string;
    dnssec_auto_update: boolean;
    rules_file: string;
    cache_enabled: boolean;
    cache_size: number;
    query_log_size: number;
    query_log_enabled: boolean;
    query_log_file: string;
    query_log_retention_days: number;
    cache_ttl_min: number;
    cache_ttl_max: number;
    cache_optimistic: boolean;
    cache_optimistic_answer_ttl: number;
    cache_optimistic_max_age: number;
    encryption: EncryptionConfig;
  };

  const defaultDNSCrypt: DNSCryptConfig = {
    enabled: false,
    listen: '',
    listens: [],
    provider_name: 'vigordns',
    private_key: '',
    resolver_secret: '',
    certificate_ttl_hours: 24
  };
  const defaultEncryption: EncryptionConfig = {
    enabled: false,
    certificate: '',
    private_key: '',
    certificate_pem: '',
    private_key_pem: '',
    dot_listen: '',
    dot_listens: [],
    doh_listen: '',
    doh_listens: [],
    doh3_listen: '',
    doh3_listens: [],
    doq_listen: '',
    doq_listens: [],
    dnscrypt: defaultDNSCrypt
  };
  const defaultAccess: DNSAccessConfig = {
    allowed_clients: [],
    denied_clients: [],
    client_rate_limit_qps: 0,
    max_concurrent_queries: 2048,
    rebinding_protection: false,
    rebinding_allow_domains: []
  };

  const activeTab = writable('overview');
  let status: Status | null = null;
  let config: Config | null = null;
  let rules: Rule[] = [];
  let logs: LogEntry[] = [];
  let metrics: MetricPoint[] = [];
  let sources: RuleSource[] = [];
  let upstreamTests: UpstreamTest[] = [];
  let testingUpstreams = false;
  let showTestModal = false;
  let sourceUrl = '';
  let sourceInterval = 360;
  let domain = '';
  let action: RuleAction = 'block';
  let localRecordDomain = '';
  let localRecordType = 'A';
  let localRecordValue = '';
  let localRecordTTL = 300;
  let busy = false;
  let message = '';
  let error = '';
  const apiTokenStorageKey = 'vigordns_api_token';
  const activeTabStorageKey = 'vigordns_active_tab';
  const navigationTabs = new Set(['overview', 'filters', 'sources', 'logs', 'upstreams', 'settings']);
  let apiToken = '';
  let navGroup: HTMLElement | undefined;
  let filterPageButton: HTMLButtonElement | undefined;
  let filterMenuOpen = false;

  function cleanList(values: string[] | undefined) {
    return (values || []).map((value) => value.trim()).filter(Boolean);
  }

  function fromLegacyList(list: string[] | undefined, legacy: string | undefined) {
    const values = cleanList(list);
    return values.length > 0 ? values : cleanList(legacy ? [legacy] : []);
  }

  function normalizeConfig(raw: Config): Config {
    const dnsListens = fromLegacyList(raw.dns_listens, raw.dns_listen);
    const rawEncryption = raw.encryption || defaultEncryption;
    const rawDNSCrypt = rawEncryption.dnscrypt || defaultDNSCrypt;
    const encryption: EncryptionConfig = {
      ...defaultEncryption,
      ...rawEncryption,
      dnscrypt: { ...defaultDNSCrypt, ...rawDNSCrypt },
      dot_listens: fromLegacyList(rawEncryption.dot_listens, rawEncryption.dot_listen),
      doh_listens: fromLegacyList(rawEncryption.doh_listens, rawEncryption.doh_listen),
      doh3_listens: fromLegacyList(rawEncryption.doh3_listens, rawEncryption.doh3_listen),
      doq_listens: fromLegacyList(rawEncryption.doq_listens, rawEncryption.doq_listen)
    };
    encryption.dot_listen = encryption.dot_listens[0] || '';
    encryption.doh_listen = encryption.doh_listens[0] || '';
    encryption.doh3_listen = encryption.doh3_listens[0] || '';
    encryption.doq_listen = encryption.doq_listens[0] || '';
    encryption.dnscrypt.listens = fromLegacyList(encryption.dnscrypt.listens, encryption.dnscrypt.listen);
    encryption.dnscrypt.listen = encryption.dnscrypt.listens[0] || '';

    if (!encryption.enabled) {
      encryption.dot_listens = [];
      encryption.doh_listens = [];
      encryption.doh3_listens = [];
      encryption.doq_listens = [];
      encryption.dot_listen = '';
      encryption.doh_listen = '';
      encryption.doh3_listen = '';
      encryption.doq_listen = '';
    }
    if (!encryption.dnscrypt.enabled) {
      encryption.dnscrypt.listens = [];
      encryption.dnscrypt.listen = '';
    }

    return {
      ...raw,
      dns_listens: dnsListens,
      dns_listen: dnsListens[0] || '',
      upstreams: cleanList(raw.upstreams),
      fallback_upstreams: cleanList(raw.fallback_upstreams),
      bootstrap_dns: cleanList(raw.bootstrap_dns),
      local_records: raw.local_records || [],
      access: { ...defaultAccess, ...(raw.access || {}), allowed_clients: cleanList(raw.access?.allowed_clients), denied_clients: cleanList(raw.access?.denied_clients), rebinding_allow_domains: cleanList(raw.access?.rebinding_allow_domains) },
      encryption
    };
  }

  function loadActiveTab() {
    const hashTab = window.location.hash.replace(/^#/, '');
    const savedTab = window.localStorage.getItem(activeTabStorageKey);
    const requestedTab = hashTab || savedTab;
    const migratedTab = requestedTab === 'rules' ? 'filters' : requestedTab;
    if (migratedTab && navigationTabs.has(migratedTab)) activeTab.set(migratedTab);
  }

  function selectTab(tab: string) {
    activeTab.set(tab);
    window.localStorage.setItem(activeTabStorageKey, tab);
    if (window.location.hash !== `#${tab}`) {
      window.history.pushState({}, '', `${window.location.pathname}${window.location.search}#${tab}`);
    }
    filterMenuOpen = false;
  }

  function syncTabFromLocation() {
    const locationTab = window.location.hash.replace(/^#/, '');
    const migratedTab = locationTab === 'rules' ? 'filters' : locationTab;
    if (migratedTab && navigationTabs.has(migratedTab)) {
      activeTab.set(migratedTab);
      window.localStorage.setItem(activeTabStorageKey, migratedTab);
      filterMenuOpen = false;
    }
  }

  function setEncryptionEnabled(enabled: boolean) {
    if (!config) return;
    config = {
      ...config,
      encryption: {
        ...config.encryption,
        enabled,
        dot_listens: enabled ? config.encryption.dot_listens : [],
        doh_listens: enabled ? config.encryption.doh_listens : [],
        doh3_listens: enabled ? config.encryption.doh3_listens : [],
        doq_listens: enabled ? config.encryption.doq_listens : [],
        dot_listen: enabled ? config.encryption.dot_listen : '',
        doh_listen: enabled ? config.encryption.doh_listen : '',
        doh3_listen: enabled ? config.encryption.doh3_listen : '',
        doq_listen: enabled ? config.encryption.doq_listen : ''
      }
    };
  }

  function setDNSCryptEnabled(enabled: boolean) {
    if (!config) return;
    config = {
      ...config,
      encryption: {
        ...config.encryption,
        dnscrypt: {
          ...config.encryption.dnscrypt,
          enabled,
          listens: enabled ? config.encryption.dnscrypt.listens : [],
          listen: enabled ? config.encryption.dnscrypt.listen : ''
        }
      }
    };
  }

  $: blockedRate = status && status.total_queries > 0
    ? Math.round((status.blocked_queries / status.total_queries) * 100)
    : 0;
  $: chartMax = Math.max(1, ...metrics.map((point) => point.queries));
  $: queryLine = chartLine('queries');
  $: blockedLine = chartLine('blocked');

  function chartLine(field: 'queries' | 'blocked') {
    const width = 720;
    const height = 174;
    const inset = 10;
    return metrics.map((point, index) => {
      const x = metrics.length > 1 ? inset + (index / (metrics.length - 1)) * (width - inset * 2) : width / 2;
      const y = height - inset - ((point[field] / chartMax) * (height - inset * 2));
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  }

  function loadApiToken() {
    const queryToken = new URLSearchParams(window.location.search).get('token');
    apiToken = queryToken ?? window.localStorage.getItem(apiTokenStorageKey) ?? '';
    if (queryToken !== null) {
      window.localStorage.setItem(apiTokenStorageKey, apiToken);
      const url = new URL(window.location.href);
      url.searchParams.delete('token');
      window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
    }
  }

  async function api<T>(path: string, options?: RequestInit): Promise<T> {
    const headers = new Headers(options?.headers);
    headers.set('Content-Type', 'application/json');
    if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
    const response = await fetch(`/api${path}`, { ...options, headers });
    const data = await response.json();
    if (!response.ok) throw new APIError(response.status, data);
    return data as T;
  }

  async function refresh() {
    error = '';
    try {
      const [nextStatus, rawConfig, nextRules, nextLogs] = await Promise.all([
        api<Status>('/status'),
        api<Config>('/config'),
        api<Rule[]>('/rules'),
        api<LogEntry[]>('/logs')
      ]);
      status = nextStatus;
      metrics = nextStatus.series || [];
      sources = nextStatus.rule_sources || [];
      config = normalizeConfig(rawConfig);
      rules = nextRules;
      logs = nextLogs;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法连接到 VigorDNS';
    }
  }

  async function addRule() {
    if (!domain.trim()) return;
    busy = true;
    message = '';
    error = '';
    try {
      await api('/rules', { method: 'POST', body: JSON.stringify({ domain: domain.trim(), action }) });
      domain = '';
      message = '规则已添加';
      await refresh();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '添加规则失败';
    } finally {
      busy = false;
    }
  }

  async function removeRule(rule: Rule) {
    busy = true;
    try {
      await api(`/rules?domain=${encodeURIComponent(rule.domain)}&action=${rule.action}`, { method: 'DELETE' });
      message = '规则已删除';
      await refresh();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '删除规则失败';
    } finally {
      busy = false;
    }
  }

  async function reloadRules() {
    busy = true;
    try {
      await api('/reload', { method: 'POST' });
      message = '规则已重新载入';
      await refresh();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '载入规则失败';
    } finally {
      busy = false;
    }
  }

  function buildConfigForSave(current: Config): Config {
    const dnsListens = cleanList(current.dns_listens);
    const encryption: EncryptionConfig = {
      ...current.encryption,
      dot_listens: current.encryption.enabled ? cleanList(current.encryption.dot_listens) : [],
      doh_listens: current.encryption.enabled ? cleanList(current.encryption.doh_listens) : [],
      doh3_listens: current.encryption.enabled ? cleanList(current.encryption.doh3_listens) : [],
      doq_listens: current.encryption.enabled ? cleanList(current.encryption.doq_listens) : [],
      dnscrypt: {
        ...current.encryption.dnscrypt,
        listens: current.encryption.dnscrypt.enabled ? cleanList(current.encryption.dnscrypt.listens) : []
      }
    };
    encryption.dot_listen = encryption.dot_listens[0] || '';
    encryption.doh_listen = encryption.doh_listens[0] || '';
    encryption.doh3_listen = encryption.doh3_listens[0] || '';
    encryption.doq_listen = encryption.doq_listens[0] || '';
    encryption.dnscrypt.listen = encryption.dnscrypt.listens[0] || '';
    return {
      ...current,
      dns_listens: dnsListens,
      dns_listen: dnsListens[0] || '',
      upstreams: cleanList(current.upstreams),
      fallback_upstreams: cleanList(current.fallback_upstreams),
      bootstrap_dns: cleanList(current.bootstrap_dns),
      dnssec_trust_anchors: cleanList(current.dnssec_trust_anchors),
      access: {
        ...current.access,
        allowed_clients: cleanList(current.access.allowed_clients),
        denied_clients: cleanList(current.access.denied_clients),
        rebinding_allow_domains: cleanList(current.access.rebinding_allow_domains)
      },
      encryption
    };
  }

  async function saveConfig() {
    if (!config) return;
    const next = buildConfigForSave(config);
    if (next.dns_listens.length === 0) {
      error = '至少配置一个普通 DNS 监听地址';
      return;
    }
    if (next.upstreams.length === 0) {
      error = '至少配置一个上游 DNS 服务器';
      return;
    }
    busy = true;
    error = '';
    try {
      config = normalizeConfig(await api<Config>('/config', { method: 'PUT', body: JSON.stringify(next) }));
      message = '配置已保存';
      await refresh();
    } catch (cause) {
      if (cause instanceof APIError && cause.status === 409 && cause.data?.config) {
        config = normalizeConfig(cause.data.config as Config);
        message = '配置已保存，部分监听或日志设置需要重启后生效';
        error = '';
      } else {
        error = cause instanceof Error ? cause.message : '保存配置失败';
      }
    } finally {
      busy = false;
    }
  }

  function addLocalRecord() {
    if (!config || !localRecordDomain.trim() || !localRecordValue.trim()) return;
    const record: LocalRecord = { domain: localRecordDomain.trim(), type: localRecordType, value: localRecordValue.trim(), ttl: Number(localRecordTTL) || 300 };
    if (config.local_records.some((item) => item.domain.toLowerCase() === record.domain.toLowerCase() && item.type === record.type && item.value === record.value)) {
      error = '本地记录已存在';
      return;
    }
    config = { ...config, local_records: [...config.local_records, record] };
    localRecordDomain = '';
    localRecordValue = '';
    message = '本地记录已添加，请保存 DNS 配置';
    error = '';
  }

  function removeLocalRecord(index: number) {
    if (!config) return;
    config = { ...config, local_records: config.local_records.filter((_, current) => current !== index) };
    message = '本地记录已移除，请保存 DNS 配置';
  }

  async function restoreConfig() {
    busy = true;
    error = '';
    try {
      config = normalizeConfig(await api<Config>('/config/restore', { method: 'POST' }));
      message = '上次配置已恢复';
      await refresh();
    } catch (cause) {
      if (cause instanceof APIError && cause.status === 409 && cause.data?.config) {
        config = normalizeConfig(cause.data.config as Config);
        message = '配置已恢复，部分设置需要重启后生效';
        error = '';
      } else {
        error = cause instanceof Error ? cause.message : '恢复配置失败';
      }
    } finally {
      busy = false;
    }
  }

  async function clearCache() {
    busy = true;
    error = '';
    try {
      await api('/cache/clear', { method: 'POST' });
      message = 'DNS 缓存已清空';
      await refresh();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '清空缓存失败';
    } finally {
      busy = false;
    }
  }

  async function saveSources(next: RuleSource[]) {
    busy = true;
    error = '';
    try {
      sources = await api<RuleSource[]>('/sources', {
        method: 'PUT',
        body: JSON.stringify(next.map((source) => ({ url: source.url, enabled: source.enabled, interval_minutes: source.interval_minutes, rule_count: source.rule_count || 0 })))
      });
      message = '规则源配置已保存';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '保存规则源失败';
    } finally {
      busy = false;
    }
  }

  async function testUpstreams() {
    if (!config) return;
    testingUpstreams = true;
    error = '';
    try {
      upstreamTests = await api<UpstreamTest[]>('/upstreams/test', { method: 'POST', body: JSON.stringify({ upstreams: cleanList(config.upstreams) }) });
      showTestModal = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '上游测试失败';
    } finally {
      testingUpstreams = false;
    }
  }

  async function addSource() {
    if (!sourceUrl.trim()) return;
    await saveSources([...sources, { url: sourceUrl.trim(), enabled: true, interval_minutes: Number(sourceInterval) || 360, rule_count: 0 }]);
    if (!error) sourceUrl = '';
  }

  async function removeSource(source: RuleSource) {
    await saveSources(sources.filter((item) => item.url !== source.url));
  }

  async function toggleSource(source: RuleSource) {
    await saveSources(sources.map((item) => item.url === source.url ? { ...item, enabled: !item.enabled } : item));
  }

  function formatDuration(value: number) {
    if (value === 0) return '0 ms';
    return `${value < 10 ? value.toFixed(2) : Math.round(value)} ms`;
  }

  function formatTime(value: string) {
    return new Date(value).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  onMount(() => {
    loadActiveTab();
    loadApiToken();
    refresh();
    const timer = window.setInterval(refresh, 10000);
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (filterMenuOpen && event.target instanceof Node && !navGroup?.contains(event.target)) filterMenuOpen = false;
    };
    const closeOnOutsideFocus = (event: FocusEvent) => {
      if (filterMenuOpen && event.target instanceof Node && !navGroup?.contains(event.target)) filterMenuOpen = false;
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && filterMenuOpen) {
        filterMenuOpen = false;
        navGroup?.querySelector<HTMLButtonElement>('.nav-toggle')?.focus();
      }
    };
    const navigateToFilters = () => {
      window.localStorage.setItem(activeTabStorageKey, 'filters');
      window.location.hash = 'filters';
      window.location.reload();
    };
    filterPageButton?.addEventListener('click', navigateToFilters);
    document.addEventListener('pointerdown', closeOnOutsidePointer);
    document.addEventListener('focusin', closeOnOutsideFocus);
    document.addEventListener('keydown', closeOnEscape);
    window.addEventListener('popstate', syncTabFromLocation);
    window.addEventListener('hashchange', syncTabFromLocation);
    return () => {
      window.clearInterval(timer);
      filterPageButton?.removeEventListener('click', navigateToFilters);
      document.removeEventListener('pointerdown', closeOnOutsidePointer);
      document.removeEventListener('focusin', closeOnOutsideFocus);
      document.removeEventListener('keydown', closeOnEscape);
      window.removeEventListener('popstate', syncTabFromLocation);
      window.removeEventListener('hashchange', syncTabFromLocation);
    };
  });
</script>

<svelte:head>
  <title>VigorDNS 控制台</title>
</svelte:head>

<div class="app-shell">
  <header class="topbar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">V</div>
      <div class="brand-copy"><strong>VigorDNS</strong><span>DNS CONTROL PLANE</span></div>
    </div>
    <nav class="main-nav" aria-label="管理台导航">
      <button class:active={$activeTab === 'overview'} aria-current={$activeTab === 'overview' ? 'page' : undefined} onclick={() => selectTab('overview')}>仪表盘</button>
      <div bind:this={navGroup} class:active={$activeTab === 'filters' || $activeTab === 'sources'} class="nav-group">
        <button type="button" class="nav-toggle" aria-haspopup="true" aria-expanded={filterMenuOpen} onclick={() => filterMenuOpen = !filterMenuOpen}>过滤器</button>
        <div class="nav-menu" role="menu" hidden={!filterMenuOpen} aria-hidden={!filterMenuOpen}><button bind:this={filterPageButton} type="button" role="menuitem" class:active={$activeTab === 'filters'} aria-current={$activeTab === 'filters' ? 'page' : undefined}>DNS 过滤器</button><button type="button" role="menuitem" class:active={$activeTab === 'sources'} onclick={() => selectTab('sources')}>远程规则源</button></div>
      </div>
      <button class:active={$activeTab === 'logs'} aria-current={$activeTab === 'logs' ? 'page' : undefined} onclick={() => selectTab('logs')}>查询日志</button>
      <button class:active={$activeTab === 'upstreams'} aria-current={$activeTab === 'upstreams' ? 'page' : undefined} onclick={() => selectTab('upstreams')}>DNS</button>
      <button class:active={$activeTab === 'settings'} aria-current={$activeTab === 'settings' ? 'page' : undefined} onclick={() => selectTab('settings')}>服务</button>
    </nav>
    <div class="connection-state" aria-live="polite"><span class="status-dot"></span><span>{status ? '服务运行中' : '连接中'}</span></div>
  </header>

  <main class="content">
    {#if error}<div class="notice error" role="alert"><span>{error}</span><button class="notice-close" aria-label="关闭提示" onclick={() => error = ''}>×</button></div>{/if}
    {#if message}<div class="notice success" role="status"><span>{message}</span><button class="notice-close" aria-label="关闭提示" onclick={() => message = ''}>×</button></div>{/if}

    {#if $activeTab === 'overview'}
      <section class="metrics-grid" aria-label="服务概览">
        <article class="metric-card"><div class="metric-label"><span class="metric-marker blue"></span>累计查询</div><strong>{status?.total_queries ?? 0}</strong><small>本次启动以来</small></article>
        <article class="metric-card"><div class="metric-label"><span class="metric-marker red"></span>已拦截</div><strong>{status?.blocked_queries ?? 0}</strong><small>{blockedRate}% 的请求被过滤</small></article>
        <article class="metric-card"><div class="metric-label"><span class="metric-marker purple"></span>活动规则</div><strong>{status?.rules ?? rules.length}</strong><small>本地与远程规则</small></article>
        <article class="metric-card"><div class="metric-label"><span class="metric-marker green"></span>平均处理时间</div><strong>{formatDuration(status?.dashboard?.average_processing_ms ?? 0)}</strong><small>DNS 请求端到端耗时</small></article>
      </section>

      <section class="surface chart-surface">
        <div class="surface-header"><div><span class="section-kicker">TRAFFIC</span><h2>请求趋势</h2></div><div class="header-tools"><span class="period-label">最近 30 分钟</span><button class="button secondary small" onclick={refresh}>刷新</button></div></div>
        <div class="chart-wrap">
          <div class="chart-ylabels"><span>{chartMax}</span><span>{Math.round(chartMax / 2)}</span><span>0</span></div>
          <svg class="traffic-chart" viewBox="0 0 720 174" role="img" aria-label="查询和拦截趋势图" preserveAspectRatio="none">
            <line x1="10" y1="10" x2="710" y2="10" class="grid-line" />
            <line x1="10" y1="87" x2="710" y2="87" class="grid-line" />
            <line x1="10" y1="164" x2="710" y2="164" class="grid-line" />
            <polyline points={queryLine} class="query-line" />
            <polyline points={blockedLine} class="blocked-line" />
          </svg>
        </div>
        <div class="chart-footer"><span><i class="query-key"></i>全部查询</span><span><i class="blocked-key"></i>已拦截</span><span class="chart-updated">每分钟聚合 · 自动刷新</span></div>
      </section>

      <section class="dashboard-grid">
        <article class="surface dashboard-card"><div class="surface-header"><div><span class="section-kicker">CLIENTS</span><h2>IP · 请求数</h2></div><button class="button ghost small" onclick={refresh}>刷新</button></div>{#if (status?.dashboard?.client_ips?.length ?? 0) === 0}<div class="empty">暂无客户端请求数据</div>{:else}<div class="data-table"><div class="data-head"><span>IP 地址</span><span>请求数</span></div>{#each status?.dashboard?.client_ips || [] as client}<div class="data-row"><b title={client.name}>{client.name}</b><span>{client.count}</span></div>{/each}</div>{/if}</article>
        <article class="surface dashboard-card"><div class="surface-header"><div><span class="section-kicker">DOMAINS</span><h2>请求域名 · 请求数</h2></div><button class="button ghost small" onclick={refresh}>刷新</button></div>{#if (status?.dashboard?.domains?.length ?? 0) === 0}<div class="empty">暂无域名请求数据</div>{:else}<div class="data-table"><div class="data-head"><span>域名</span><span>请求数</span></div>{#each status?.dashboard?.domains || [] as item}<div class="data-row"><b title={item.name}>{item.name}</b><span>{item.count}</span></div>{/each}</div>{/if}</article>
        <article class="surface dashboard-card"><div class="surface-header"><div><span class="section-kicker">BLOCKED</span><h2>被拦截域名 · 请求数</h2></div><button class="button ghost small" onclick={refresh}>刷新</button></div>{#if (status?.dashboard?.blocked_domains?.length ?? 0) === 0}<div class="empty">暂无被拦截域名数据</div>{:else}<div class="data-table"><div class="data-head"><span>域名</span><span>请求数</span></div>{#each status?.dashboard?.blocked_domains || [] as item}<div class="data-row"><b title={item.name}>{item.name}</b><span>{item.count}</span></div>{/each}</div>{/if}</article>
        <article class="surface dashboard-card"><div class="surface-header"><div><span class="section-kicker">UPSTREAMS</span><h2>上游服务器 · 请求数 · 响应时间</h2></div><button class="button ghost small" onclick={refresh}>刷新</button></div>{#if (status?.dashboard?.upstreams?.length ?? 0) === 0}<div class="empty">暂无上游请求数据</div>{:else}<div class="data-table upstream-table"><div class="data-head"><span>服务器</span><span>请求数</span><span>响应时间</span></div>{#each status?.dashboard?.upstreams || [] as upstream}<div class="data-row"><b title={upstream.address}>{upstream.address}</b><span>{upstream.count}</span><span>{formatDuration(upstream.average_duration_ms)}</span></div>{/each}</div>{/if}</article>
      </section>
    {:else if $activeTab === 'filters'}
      <section class="surface form-surface rule-create"><div class="form-title"><div><span class="section-kicker">DNS FILTERS</span><h2>添加 DNS 过滤规则</h2><p>支持 `example.com` 和 AdGuard `||domain.example^` 格式。</p></div><div class="form-title-actions"><span class="count-pill">{rules.length} 条规则</span><button class="button secondary small" disabled={busy} onclick={reloadRules}>重新载入</button></div></div><div class="rule-form"><input aria-label="域名" placeholder="输入域名，例如 ads.example.com" bind:value={domain} onkeydown={(event) => event.key === 'Enter' && addRule()} /><select aria-label="动作" bind:value={action}><option value="block">拦截</option><option value="allow">放行</option></select><button class="button primary" disabled={busy || !domain.trim()} onclick={addRule}>添加规则</button></div></section>
      <section class="surface table-surface"><div class="surface-header"><div><span class="section-kicker">DNS FILTERS</span><h2>DNS 过滤器</h2></div><div class="rule-legend"><span><i class="legend-block"></i>拦截</span><span><i class="legend-allow"></i>放行</span></div></div>{#if rules.length === 0}<div class="empty">暂无规则。添加第一条过滤规则。</div>{:else}<div class="wide-table"><div class="wide-head"><span>域名</span><span>动作</span><span>来源</span><span></span></div>{#each rules as rule}<div class="wide-row"><b>{rule.domain}</b><span class:allow={rule.action === 'allow'} class="badge">{rule.action === 'allow' ? '放行' : '拦截'}</span><span class="muted">rules.txt</span><button class="text-danger" disabled={busy} onclick={() => removeRule(rule)}>删除</button></div>{/each}</div>{/if}</section>
    {:else if $activeTab === 'logs'}
      <section class="surface table-surface"><div class="surface-header"><div><span class="section-kicker">OBSERVABILITY</span><h2>最近请求</h2><span class="subtle-text">保留最近 {logs.length} 条内存记录 · 查看 DNS 请求、过滤结果和处理耗时</span></div><button class="button secondary small" onclick={refresh}>刷新</button></div>{#if logs.length === 0}<div class="empty">还没有 DNS 查询记录</div>{:else}<div class="wide-table log-table"><div class="wide-head"><span>时间</span><span>域名</span><span>类型</span><span>结果</span><span>耗时</span></div>{#each logs as entry}<div class="wide-row"><time>{formatTime(entry.time)}</time><b>{entry.domain}</b><span class="muted">{entry.type}</span><span class:allow={entry.action !== 'block'} class="badge">{entry.action === 'block' ? '已拦截' : entry.action === 'cached' ? '缓存命中' : '已转发'}</span><span class="muted">{entry.duration_ms} ms</span></div>{/each}</div>{/if}</section>
    {:else if $activeTab === 'upstreams'}
      {#if config}
        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">RESOLUTION</span><h2>上游解析</h2><p>管理上游、缓存、过滤响应、DNSSEC 和本地记录。主上游负责常规请求，备用上游只在主池无可用响应时接管。</p></div><div class="heading-actions"><span class="live-badge"><span class="status-dot"></span>实时配置</span><button class="button secondary small" disabled={testingUpstreams || config.upstreams.length === 0} onclick={testUpstreams}>{testingUpstreams ? '测试中…' : '测试上游'}</button></div></div>
          <div class="upstream-layout"><div class="config-card primary-upstream"><ListEditor label="主上游 DNS" hint="按顺序填写地址；最多 32 个" placeholder="1.1.1.1:53 或 https://dns.example/dns-query" maxItems={32} bind:values={config.upstreams} /><div class="protocol-hints"><span>DNS <code>1.1.1.1:53</code></span><span>DoT <code>tls://dns.example:853</code></span><span>DoH <code>https://dns.example/dns-query</code></span><span>DoH3 <code>h3://dns.example/dns-query</code></span><span>DoQ <code>quic://dns.example:853</code></span><span>DNSCrypt <code>sdns://…</code></span></div></div><div class="config-card mode-card"><div class="field-heading"><span class="field-label">上游使用策略</span><span class="info-badge">请求分发</span></div><select bind:value={config.upstream_mode} aria-label="上游模式"><option value="load_balance">负载均衡</option><option value="parallel">并行请求</option><option value="fastest_addr">最快 IP 地址</option></select><div class="mode-list"><div class:chosen={config.upstream_mode === 'load_balance'}><b>负载均衡</b><span>按健康状态轮转，额外流量最少，适合常规部署。</span></div><div class:chosen={config.upstream_mode === 'parallel'}><b>并行请求</b><span>同时询问多个上游，采用首个有效响应，容错更快但会增加请求量。</span></div><div class:chosen={config.upstream_mode === 'fastest_addr'}><b>最快 IP 地址</b><span>解析后探测公网地址，仅适合明确需要 CDN 多线路优化的场景。</span></div></div></div></div>
          <div class="two-column-config"><div class="config-card"><ListEditor label="备用 DNS" hint="主上游不可用、超时或返回失败时使用" placeholder="tls://backup.example:853" maxItems={32} bind:values={config.fallback_upstreams} /></div><div class="config-card"><ListEditor label="Bootstrap DNS" hint="只用于解析加密上游域名；建议填写 IP:53" placeholder="1.1.1.1:53" maxItems={16} bind:values={config.bootstrap_dns} /></div></div>
          <div class="inline-setting"><div><span class="field-label">单个上游超时</span><small>连接和查询的最大等待时间</small></div><div class="unit-input"><input type="number" min="1" bind:value={config.upstream_timeout_seconds} aria-label="上游超时秒数" /><span>秒</span></div></div>
        </section>

        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">CACHE & POLICY</span><h2>缓存与响应策略</h2><p>将性能配置和拦截结果放在同一处，便于理解它们对客户端响应的影响。</p></div></div>
          <div class="policy-grid"><div class="config-card cache-config"><div class="card-title-row"><div><h3>DNS 缓存</h3><p>按字节容量运行分片 LRU 缓存，支持负缓存和过期后台刷新。</p></div><div class="toggle-pair"><label class="switch-label"><input type="checkbox" bind:checked={config.cache_enabled} /><span class="switch"></span><b>启用</b></label><label class="switch-label"><input type="checkbox" bind:checked={config.cache_optimistic} /><span class="switch"></span><b>乐观缓存</b></label></div></div><div class="settings-grid three"><label class="field"><span class="field-label">缓存大小（字节）</span><input type="number" min="65536" bind:value={config.cache_size} /><small>建议至少 4194304 字节</small></label><label class="field"><span class="field-label">TTL 最小值</span><input type="number" min="0" bind:value={config.cache_ttl_min} /><small>秒，0 表示不限制</small></label><label class="field"><span class="field-label">TTL 最大值</span><input type="number" min="0" bind:value={config.cache_ttl_max} /><small>秒，0 表示不限制</small></label><label class="field"><span class="field-label">乐观缓存应答 TTL</span><input type="number" min="1" bind:value={config.cache_optimistic_answer_ttl} /><small>过期响应返回给客户端的 TTL</small></label><label class="field"><span class="field-label">乐观缓存最大寿命</span><input type="number" min="1" bind:value={config.cache_optimistic_max_age} /><small>过期后继续保留旧响应的秒数</small></label></div><div class="cache-footer"><div class="mini-stats"><span><b>{status?.cache?.entries ?? 0}</b><small>条目</small></span><span><b>{Math.round((status?.cache?.used_bytes ?? 0) / 1024)} KB</b><small>已用空间</small></span><span><b>{Math.round((status?.cache?.hit_rate ?? 0) * 100)}%</b><small>命中率</small></span><span><b>{status?.cache?.refresh_failure ?? 0}</b><small>刷新失败</small></span></div><button class="button secondary small" disabled={busy} onclick={clearCache}>清空缓存</button></div></div>
            <div class="config-card blocking-config"><div class="card-title-row"><div><h3>拦截响应</h3><p>选择命中过滤规则后返回给客户端的响应类型。</p></div><span class="info-badge">{config.blocking_mode}</span></div><label class="field"><span class="field-label">拦截模式</span><select bind:value={config.blocking_mode} aria-label="拦截模式"><option value="default">默认（空 IP）</option><option value="nxdomain">NXDOMAIN</option><option value="null_ip">空 IP</option><option value="custom_ip">自定义 IP</option><option value="refused">REFUSED</option></select><small>{config.blocking_mode === 'default' || config.blocking_mode === 'null_ip' ? '返回 0.0.0.0 或 ::。' : config.blocking_mode === 'nxdomain' ? '返回 NXDOMAIN，并提供负缓存 SOA。' : config.blocking_mode === 'refused' ? '返回 REFUSED，客户端通常不会缓存。' : '返回下方自定义地址。'}</small></label>{#if config.blocking_mode === 'custom_ip'}<div class="settings-grid two"><label class="field"><span class="field-label">IPv4 响应地址</span><input type="text" bind:value={config.blocking_ipv4} placeholder="0.0.0.0" /></label><label class="field"><span class="field-label">IPv6 响应地址</span><input type="text" bind:value={config.blocking_ipv6} placeholder="::" /></label></div>{/if}<label class="field compact-field"><span class="field-label">被拦截响应 TTL</span><input type="number" min="0" bind:value={config.blocked_response_ttl} /><small>秒，客户端缓存拦截结果的时间</small></label></div></div>
        </section>

        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">DNSSEC</span><h2>DNSSEC 验证</h2><p>控制是否请求 DNSSEC 数据以及是否在本地验证签名链。</p></div><span class="info-badge">{config.dnssec_validate ? '本地验证开启' : '本地验证关闭'}</span></div><div class="toggle-grid"><label class="toggle-setting"><input type="checkbox" bind:checked={config.enable_dnssec} /><span><b>向上游请求 DNSSEC</b><small>为未携带 DO 标志的请求补充 DNSSEC 数据。</small></span></label><label class="toggle-setting"><input type="checkbox" bind:checked={config.dnssec_validate} /><span><b>启用本地 DNSSEC 验证</b><small>使用内置或配置的信任锚校验签名链。</small></span></label><label class="toggle-setting"><input type="checkbox" bind:checked={config.dnssec_auto_update} /><span><b>自动更新根信任锚</b><small>通过当前信任链验证后安全写入受控文件。</small></span></label></div><div class="dnssec-grid"><ListEditor label="手工 DNSKEY 信任锚" hint="每行一条；留空使用内置 IANA 根信任锚" placeholder=". 172800 IN DNSKEY 257 3 8 …" code bind:values={config.dnssec_trust_anchors} /><label class="field"><span class="field-label">受控信任锚文件</span><input type="text" bind:value={config.dnssec_trust_anchor_file} placeholder="data/dnssec/root-auto.key" /><small>与手工信任锚二选一；文件变更会自动验证并热重载。</small></label></div><div class="stat-chips"><span class="positive">Secure <b>{status?.dnssec?.secure ?? 0}</b></span><span>Insecure <b>{status?.dnssec?.insecure ?? 0}</b></span><span class="negative">Bogus <b>{status?.dnssec?.bogus ?? 0}</b></span><span>Indeterminate <b>{status?.dnssec?.indeterminate ?? 0}</b></span></div></section>

        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">LOCAL DNS</span><h2>本地记录</h2><p>本地记录优先于缓存和上游，适合内网服务与自定义域名。</p></div></div><div class="record-form"><input type="text" bind:value={localRecordDomain} placeholder="域名，例如 nas.home.arpa" aria-label="本地记录域名" /><select bind:value={localRecordType} aria-label="本地记录类型"><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="TXT">TXT</option></select><input type="text" bind:value={localRecordValue} placeholder="记录值" aria-label="本地记录值" /><div class="unit-input"><input type="number" min="1" bind:value={localRecordTTL} aria-label="本地记录 TTL" /><span>秒</span></div><button class="button secondary" disabled={!localRecordDomain.trim() || !localRecordValue.trim()} onclick={addLocalRecord}>添加记录</button></div>{#if config.local_records.length === 0}<div class="empty compact-empty">暂无本地记录</div>{:else}<div class="record-list">{#each config.local_records as record, index}<div class="record-row"><b>{record.domain}</b><span class="badge allow">{record.type}</span><code>{record.value}</code><small>TTL {record.ttl}s</small><button class="text-danger" onclick={() => removeLocalRecord(index)}>删除</button></div>{/each}</div>{/if}</section>
        <div class="save-bar"><div><span class="save-bar-title">解析配置</span><span>变更仅在保存后提交</span></div><div class="save-actions"><button class="button secondary" disabled={testingUpstreams || config.upstreams.length === 0} onclick={testUpstreams}>{testingUpstreams ? '测试中…' : '测试上游'}</button><button class="button primary" disabled={busy} onclick={saveConfig}>保存 DNS 配置</button></div></div>
      {/if}
    {:else if $activeTab === 'sources'}
      <section class="surface form-surface"><div class="section-heading"><div><span class="section-kicker">FILTER SOURCES</span><h2>远程规则源</h2><p>订阅 AdGuard 或 hosts 格式规则，拉取失败时保留上一份成功数据。</p></div><span class="count-pill">{sources.length} 个来源</span></div><div class="source-form"><input type="url" placeholder="https://example.com/adguard.txt" aria-label="规则源 URL" bind:value={sourceUrl} /><div class="unit-input"><input type="number" min="1" bind:value={sourceInterval} aria-label="更新间隔分钟" /><span>分钟</span></div><button class="button primary" disabled={busy || !sourceUrl.trim()} onclick={addSource}>添加来源</button></div>{#if sources.length === 0}<div class="empty">暂无远程规则源</div>{:else}<div class="source-list">{#each sources as source}<div class="source-row"><label class="switch-label source-switch"><input type="checkbox" checked={source.enabled} onchange={() => toggleSource(source)} /><span class="switch"></span></label><div class="source-main"><b title={source.url}>{source.url}</b><small>{source.last_error || (source.last_updated ? `上次更新 ${formatTime(source.last_updated)}` : '等待首次更新')} · {source.rule_count} 条规则</small></div><button class="text-danger" disabled={busy} onclick={() => removeSource(source)}>删除</button></div>{/each}</div>{/if}</section>
    {:else}
      {#if config}
        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">SERVICE</span><h2>普通 DNS 服务</h2><p>管理监听、日志、客户端安全策略和对外提供的加密 DNS 服务。每个地址同时绑定 UDP 和 TCP；首项作为兼容主地址。最多 16 个。</p></div><div class="heading-actions"><span class="info-badge">UDP + TCP</span><button class="button secondary small" disabled={busy} onclick={restoreConfig}>恢复上次配置</button></div></div><ListEditor label="普通 DNS 监听地址" hint="端口通常使用 53；开发环境可以使用其他端口" placeholder=":53 或 192.0.2.10:53" maxItems={16} code bind:values={config.dns_listens} /></section>
        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">LOGGING</span><h2>查询日志持久化</h2><p>内存日志和仪表盘始终可用；持久化日志会包含客户端 IP 与查询域名。</p></div><span class="info-badge">重启后生效</span></div><div class="settings-grid four"><label class="toggle-setting"><input type="checkbox" bind:checked={config.query_log_enabled} /><span><b>启用 JSONL 持久化</b><small>按日期异步写入日志文件。</small></span></label><label class="field"><span class="field-label">内存日志条数</span><input type="number" min="1" bind:value={config.query_log_size} /><small>API 保留的最近记录数。</small></label><label class="field"><span class="field-label">文件前缀</span><input type="text" bind:value={config.query_log_file} placeholder="data/querylog" /><small>例如 data/querylog-2026-09-07.jsonl</small></label><label class="field"><span class="field-label">保留天数</span><input type="number" min="1" max="365" bind:value={config.query_log_retention_days} /><small>1–365 天。</small></label></div></section>
        <section class="surface config-section"><div class="section-heading"><div><span class="section-kicker">ACCESS & SAFETY</span><h2>访问控制与安全</h2><p>限制客户端来源、控制资源使用，并阻止公网域名返回私网地址。</p></div></div><div class="settings-grid two"><ListEditor label="允许的客户端" hint="IP 或 CIDR；留空允许所有客户端" placeholder="192.0.2.0/24" code bind:values={config.access.allowed_clients} /><ListEditor label="拒绝的客户端" hint="拒绝列表优先于允许列表" placeholder="192.0.2.10" code bind:values={config.access.denied_clients} /><label class="field"><span class="field-label">单客户端速率限制</span><div class="unit-input"><input type="number" min="0" bind:value={config.access.client_rate_limit_qps} /><span>QPS</span></div><small>0 表示不限制。</small></label><label class="field"><span class="field-label">最大并发查询</span><div class="unit-input"><input type="number" min="1" bind:value={config.access.max_concurrent_queries} /><span>个</span></div><small>超过上限返回 SERVFAIL。</small></label><label class="toggle-setting"><input type="checkbox" bind:checked={config.access.rebinding_protection} /><span><b>启用 DNS Rebinding 防护</b><small>阻止公网域名返回私网、回环或链路本地地址。</small></span></label><ListEditor label="Rebinding 例外域名" hint="可信内网域名" placeholder="home.arpa" bind:values={config.access.rebinding_allow_domains} /></div></section>
      {/if}
      {#if config}<section class="surface config-section encryption-section"><div class="section-heading"><div><span class="section-kicker">ENCRYPTED DNS</span><h2>加密 DNS 服务</h2><p>配置对外提供的 DoT、DoH、DoH3、DoQ 和 DNSCrypt 服务。证书、私钥或监听变更后需要重启。</p></div><span class:running={status?.dnscrypt?.running || config.encryption.enabled} class="state-pill">{config.encryption.enabled ? '已启用' : '未启用'}</span></div><label class="toggle-setting encryption-toggle"><input type="checkbox" bind:checked={config.encryption.enabled} onchange={(event) => setEncryptionEnabled((event.currentTarget as HTMLInputElement).checked)} /><span><b>启用加密 DNS 监听</b><small>启用后才会绑定下方 DoT、DoH、DoH3、DoQ 地址。</small></span></label><div class="credential-grid"><label class="field"><span class="field-label">TLS 证书路径</span><input type="text" bind:value={config.encryption.certificate} placeholder="data/tls/server.crt" /></label><label class="field"><span class="field-label">TLS 私钥路径</span><input type="text" bind:value={config.encryption.private_key} placeholder="data/tls/server.key" /></label><label class="field"><span class="field-label">TLS 证书 PEM</span><textarea class="pem-input" bind:value={config.encryption.certificate_pem} rows="5" placeholder="-----BEGIN CERTIFICATE-----" aria-label="TLS 证书 PEM 内容"></textarea><small>填写后优先使用粘贴内容。</small></label><label class="field"><span class="field-label">TLS 私钥 PEM</span><textarea class="pem-input" bind:value={config.encryption.private_key_pem} rows="5" placeholder="-----BEGIN PRIVATE KEY-----（留空保持已保存私钥）" aria-label="TLS 私钥 PEM 内容"></textarea><small>私钥不会通过 API 返回。</small></label></div><div class="protocol-heading"><div><span class="section-kicker">INBOUND PROTOCOLS</span><p>每行一个监听地址；placeholder 使用协议标准端口。</p></div></div><div class="protocol-grid"><div class="protocol-card"><div class="protocol-title"><b>DoT</b><span>DNS over TLS</span></div><ListEditor hint="默认端口 :853" placeholder=":853" disabled={!config.encryption.enabled} code bind:values={config.encryption.dot_listens} /></div><div class="protocol-card"><div class="protocol-title"><b>DoH</b><span>DNS over HTTPS</span></div><ListEditor hint="默认端口 :443" placeholder=":443" disabled={!config.encryption.enabled} code bind:values={config.encryption.doh_listens} /></div><div class="protocol-card"><div class="protocol-title"><b>DoH3</b><span>DNS over HTTP/3</span></div><ListEditor hint="默认端口 :443" placeholder=":443" disabled={!config.encryption.enabled} code bind:values={config.encryption.doh3_listens} /></div><div class="protocol-card"><div class="protocol-title"><b>DoQ</b><span>DNS over QUIC</span></div><ListEditor hint="默认端口 :853" placeholder=":853" disabled={!config.encryption.enabled} code bind:values={config.encryption.doq_listens} /></div></div><div class="dnscrypt-card"><div class="section-heading"><div><span class="section-kicker">DNSCRYPT V2</span><h3>DNSCrypt 服务</h3><p>Provider 密钥首次启用时自动生成，客户端 stamp 会在服务运行后显示。</p></div><label class="toggle-setting"><input type="checkbox" bind:checked={config.encryption.dnscrypt.enabled} onchange={(event) => setDNSCryptEnabled((event.currentTarget as HTMLInputElement).checked)} /><span><b>启用 DNSCrypt</b><small>{status?.dnscrypt?.running ? '运行中' : '重启后生效'}</small></span></label></div><div class="dnscrypt-meta"><span class:running={status?.dnscrypt?.running} class="state-pill">{status?.dnscrypt?.running ? '运行中' : '未运行'}</span><span>{status?.dnscrypt?.listen || '未配置监听'}</span>{#if status?.dnscrypt?.stamp}<code title={status.dnscrypt.stamp}>{status.dnscrypt.stamp}</code>{/if}</div><div class="dnscrypt-grid"><div><ListEditor label="DNSCrypt 监听地址" hint="UDP 和 TCP 都会绑定；默认端口 :443" placeholder=":443" disabled={!config.encryption.dnscrypt.enabled} code bind:values={config.encryption.dnscrypt.listens} /></div><div class="settings-grid two"><label class="field"><span class="field-label">Provider 名称</span><input type="text" bind:value={config.encryption.dnscrypt.provider_name} placeholder="vigordns" /></label><label class="field"><span class="field-label">证书有效期（小时）</span><input type="number" min="1" bind:value={config.encryption.dnscrypt.certificate_ttl_hours} /></label><label class="field"><span class="field-label">Provider 私钥</span><input type="password" autocomplete="new-password" bind:value={config.encryption.dnscrypt.private_key} placeholder="留空保持已保存私钥" /><small>32 字节种子或 64 字节私钥，十六进制。</small></label><label class="field"><span class="field-label">Resolver secret</span><input type="password" autocomplete="new-password" bind:value={config.encryption.dnscrypt.resolver_secret} placeholder="留空保持已保存 secret" /><small>留空时首次启用自动生成。</small></label></div></div></div><div class="save-bar inline-save"><div><span class="save-bar-title">服务配置</span><span>监听、日志与加密设置可能需要重启</span></div><button class="button primary" disabled={busy} onclick={saveConfig}>保存服务设置</button></div></section>{/if}
    {/if}
  </main>

  {#if showTestModal}
    <div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && (showTestModal = false)}>
      <div class="test-modal" role="dialog" aria-modal="true" aria-labelledby="test-modal-title">
        <div class="modal-heading"><div><span class="section-kicker">UPSTREAM CHECK</span><h2 id="test-modal-title">上游测试结果</h2></div><button class="modal-close" title="关闭" aria-label="关闭" onclick={() => showTestModal = false}>×</button></div>
        <div class="modal-body">{#each upstreamTests as test}<div class="test-result"><span class:test-failed={!test.success} class="health-indicator"></span><b>{test.address}</b><span>{test.protocol}</span><span class:test-failed={!test.success} class="test-latency">{test.success ? `${test.latency_ms} ms` : test.error}</span></div>{/each}</div>
        <div class="modal-actions"><button class="button primary" onclick={() => showTestModal = false}>完成</button></div>
      </div>
    </div>
  {/if}
</div>
