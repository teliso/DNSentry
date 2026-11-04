import type { Webhook, LogDays, AuthStatus, Config, ServiceInfo, MetricPoint, ConfigVersion, LocalSummary, LogPage, LogQuery, Rule, RuleAction, RuleCheck, Protection, RulePage, RuleQuery, RuleSource, Status, UpstreamTest } from './types';

const TOKEN_KEY = 'dnsentry_api_token';

export class APIError extends Error {
  constructor(
    readonly status: number,
    readonly data: { error?: string } | null
  ) {
    super(data?.error || `请求失败 (${status})`);
    this.name = 'APIError';
  }
}

let token = '';
let onUnauthorized: () => void = () => {};

/** Reads `?token=` (persisting it) or the previously saved token. */
export function initToken() {
  const url = new URL(window.location.href);
  const fromQuery = url.searchParams.get('token');
  try {
    if (fromQuery !== null) {
      token = fromQuery;
      localStorage.setItem(TOKEN_KEY, token);
      url.searchParams.delete('token');
      history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
    } else {
      token = localStorage.getItem(TOKEN_KEY) ?? '';
    }
  } catch {
    token = fromQuery ?? '';
  }
}

export function setToken(value: string) {
  token = value.trim();
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable: keep the token in memory only */
  }
}

export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const headers = new Headers();
  const raw = typeof body === 'string'; // a configuration file is sent as it is
  if (body !== undefined) headers.set('Content-Type', raw ? 'application/yaml' : 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body)
  });
  const text = await response.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error body */
  }
  if (!response.ok) {
    if (response.status === 401) onUnauthorized();
    throw new APIError(response.status, data as APIError['data']);
  }
  return data as T;
}

/** Fetches `path` with the API credentials and hands the response to the browser as a file download. */
async function download(path: string, fallbackName: string): Promise<void> {
  const headers = new Headers();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`/api${path}`, { headers });
  if (!response.ok) {
    if (response.status === 401) onUnauthorized();
    let data: APIError['data'] = null;
    try {
      data = JSON.parse(await response.text());
    } catch {
      /* non-JSON error body */
    }
    throw new APIError(response.status, data);
  }
  const name = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function toParams(query: Record<string, string | number | undefined>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== '') params.set(key, String(value));
  return params;
}

export const api = {
  status: () => request<Status>('/status'),
  logs: (query: LogQuery) => request<LogPage>(`/logs?${toParams(query)}`),
  config: () => request<Config>('/config'),
  saveConfig: (config: Config) => request<Config>('/config', 'PUT', config),
  configHistory: () => request<ConfigVersion[]>('/config/history'),
  restoreConfig: (id?: string) => request<Config>('/config/restore', 'POST', id ? { id } : undefined),
  authStatus: () => request<AuthStatus>('/auth'),
  login: (username: string, password: string) => request<AuthStatus>('/login', 'POST', { username, password }),
  logout: () => request<{ status: string }>('/logout', 'POST'),
  setLogin: (username: string, password: string, currentPassword: string) =>
    request<AuthStatus>('/auth', 'PUT', { username, password, current_password: currentPassword }),
  removeLogin: (currentPassword: string) => request<AuthStatus>('/auth', 'DELETE', { current_password: currentPassword }),
  services: () => request<ServiceInfo[]>('/services'),
  stats: (range: string) => request<MetricPoint[]>(`/stats?range=${range}`),
  testWebhook: (hook: Pick<Webhook, 'url' | 'format' | 'name'>) => request<{ status: string }>('/notifications/test', 'POST', hook),
  logDays: () => request<LogDays>('/logs/days'),
  exportLogs: (format: 'csv' | 'json', query: { search?: string; action?: string; date?: string }) => download(`/logs/export?${toParams({ ...query, format })}`, `dnsentry-logs.${format}`),
  exportConfig: () => download('/config/export', 'dnsentry-config.yaml'),
  importConfig: (yaml: string) => request<Config>('/config/import', 'POST', yaml),
  setProtection: (enabled: boolean, durationMinutes = 0) => request<Protection>('/protection', 'POST', { enabled, duration_minutes: durationMinutes }),
  clearCache: () => request<{ status: string }>('/cache/clear', 'POST'),
  testUpstreams: (upstreams: string[]) => request<UpstreamTest[]>('/upstreams/test', 'POST', { upstreams }),
  rules: (query: RuleQuery) => request<RulePage>(`/rules?${toParams(query)}`),
  checkRule: (domain: string) => request<RuleCheck>(`/rules/check?domain=${encodeURIComponent(domain)}`),
  localRules: () => request<{ text: string }>('/rules/local').then((result) => result.text),
  saveLocalRules: (text: string) => request<LocalSummary>('/rules/local', 'PUT', { text }),
  addRule: (domain: string, action: RuleAction) => request<Rule>('/rules', 'POST', { domain, action }),
  deleteRule: (rule: Pick<Rule, 'domain' | 'action'>) =>
    request(`/rules?domain=${encodeURIComponent(rule.domain)}&action=${rule.action}`, 'DELETE'),
  reloadRules: () => request('/reload', 'POST'),
  sources: () => request<RuleSource[]>('/sources'),
  saveSources: (sources: RuleSource[]) => request<RuleSource[]>('/sources', 'PUT', sources),
  refreshSources: (url = '') => request<RuleSource[]>('/sources/refresh', 'POST', { url })
};
