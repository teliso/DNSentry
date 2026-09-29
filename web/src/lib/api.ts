import type { Config, LogEntry, Rule, RuleAction, RuleSource, Status, UpstreamTest } from './types';

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
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
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

export const api = {
  status: () => request<Status>('/status'),
  logs: () => request<LogEntry[] | null>('/logs').then((list) => list ?? []),
  config: () => request<Config>('/config'),
  saveConfig: (config: Config) => request<Config>('/config', 'PUT', config),
  restoreConfig: () => request<Config>('/config/restore', 'POST'),
  clearCache: () => request<{ status: string }>('/cache/clear', 'POST'),
  testUpstreams: (upstreams: string[]) => request<UpstreamTest[]>('/upstreams/test', 'POST', { upstreams }),
  rules: () => request<Rule[] | null>('/rules').then((list) => list ?? []),
  addRule: (domain: string, action: RuleAction) => request('/rules', 'POST', { domain, action }),
  deleteRule: (rule: Pick<Rule, 'domain' | 'action'>) =>
    request(`/rules?domain=${encodeURIComponent(rule.domain)}&action=${rule.action}`, 'DELETE'),
  reloadRules: () => request('/reload', 'POST'),
  sources: () => request<RuleSource[]>('/sources'),
  saveSources: (sources: RuleSource[]) => request<RuleSource[]>('/sources', 'PUT', sources)
};
