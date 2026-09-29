import { api, APIError, initToken, setToken, setUnauthorizedHandler } from './api';
import { normalizeConfig, serializeConfig, validateConfig } from './config';
import { toasts } from './toast.svelte';
import type { Config, LogEntry, Rule, RuleAction, RuleSource, Status, UpstreamTest } from './types';

const POLL_INTERVAL_MS = 10_000;

function messageOf(cause: unknown, fallback: string): string {
  if (cause instanceof APIError) return cause.message;
  if (cause instanceof TypeError) return '无法连接到 VigorDNS 服务';
  return cause instanceof Error ? cause.message : fallback;
}

/** Client-side state of the console: live data, the saved config and the editable draft. */
class ConsoleStore {
  status = $state.raw<Status | null>(null);
  logs = $state.raw<LogEntry[]>([]);
  rules = $state.raw<Rule[]>([]);
  rulesLoaded = $state(false);
  online = $state(false);
  busy = $state(false);
  tokenRequired = $state(false);

  /** Config as last returned by the server. */
  saved = $state.raw<Config | null>(null);
  /** Editable copy bound to the settings forms. */
  draft = $state<Config | null>(null);

  sources = $derived<RuleSource[]>(this.status?.rule_sources ?? []);
  dirty = $derived(
    this.draft !== null && this.saved !== null && JSON.stringify(serializeConfig(this.draft)) !== JSON.stringify(serializeConfig(this.saved))
  );


  async start() {
    initToken();
    setUnauthorizedHandler(() => {
      this.tokenRequired = true;
    });
    await Promise.all([this.refreshLive(), this.loadConfig()]);
    window.setInterval(() => {
      if (!document.hidden) void this.refreshLive();
    }, POLL_INTERVAL_MS);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) void this.refreshLive();
    });
  }

  /** Runs a mutation with the shared busy flag and turns failures into toasts. */
  private async act(fn: () => Promise<void>, failure: string): Promise<boolean> {
    this.busy = true;
    try {
      await fn();
      return true;
    } catch (cause) {
      toasts.error(messageOf(cause, failure));
      return false;
    } finally {
      this.busy = false;
    }
  }

  async refreshLive() {
    try {
      const [status, logs] = await Promise.all([api.status(), api.logs()]);
      this.status = status;
      this.logs = logs;
      this.online = true;
      this.tokenRequired = false;
    } catch (cause) {
      if (this.online) toasts.error(messageOf(cause, '无法连接到 VigorDNS 服务'));
      this.online = false;
    }
  }

  async submitToken(token: string) {
    setToken(token);
    this.tokenRequired = false;
    await Promise.all([this.refreshLive(), this.loadConfig()]);
  }

  private adopt(raw: Config) {
    this.saved = normalizeConfig(raw);
    this.draft = JSON.parse(JSON.stringify(this.saved)) as Config;
  }

  async loadConfig() {
    try {
      this.adopt(await api.config());
    } catch (cause) {
      if (!(cause instanceof APIError && cause.status === 401)) toasts.error(messageOf(cause, '读取配置失败'));
    }
  }

  discardDraft() {
    if (this.saved) this.draft = JSON.parse(JSON.stringify(this.saved)) as Config;
  }

  /** Shared handling for PUT /config and POST /config/restore, which answer 409 when a restart is needed. */
  private async applyConfigResult(call: () => Promise<Config>, done: string, restartNote: string, failure: string) {
    return this.act(async () => {
      try {
        this.adopt(await call());
        toasts.success(done);
      } catch (cause) {
        if (cause instanceof APIError && cause.status === 409 && cause.data?.config) {
          this.adopt(cause.data.config);
          toasts.info(restartNote);
        } else {
          throw cause;
        }
      }
      await this.refreshLive();
    }, failure);
  }

  async saveConfig() {
    if (!this.draft) return;
    const payload = serializeConfig(this.draft);
    const problem = validateConfig(payload);
    if (problem) {
      toasts.error(problem);
      return;
    }
    await this.applyConfigResult(() => api.saveConfig(payload), '配置已保存', '配置已保存，部分监听或日志设置需要重启后生效', '保存配置失败');
  }

  async restoreConfig() {
    await this.applyConfigResult(() => api.restoreConfig(), '已恢复上次配置', '配置已恢复，部分设置需要重启后生效', '恢复配置失败');
  }

  async clearCache() {
    await this.act(async () => {
      await api.clearCache();
      toasts.success('DNS 缓存已清空');
      await this.refreshLive();
    }, '清空缓存失败');
  }

  async testUpstreams(addresses: string[]): Promise<UpstreamTest[] | null> {
    let result: UpstreamTest[] | null = null;
    await this.act(async () => {
      result = await api.testUpstreams(addresses);
    }, '上游测试失败');
    return result;
  }

  async loadRules() {
    try {
      this.rules = await api.rules();
      this.rulesLoaded = true;
    } catch (cause) {
      toasts.error(messageOf(cause, '读取规则失败'));
    }
  }

  async addRule(domain: string, action: RuleAction): Promise<boolean> {
    const ok = await this.act(async () => {
      await api.addRule(domain, action);
      toasts.success('规则已添加');
      await Promise.all([this.loadRules(), this.refreshLive()]);
    }, '添加规则失败');
    return ok;
  }

  async removeRule(rule: Rule) {
    await this.act(async () => {
      await api.deleteRule({ domain: rule.domain, action: rule.action });
      toasts.success('规则已删除');
      await Promise.all([this.loadRules(), this.refreshLive()]);
    }, '删除规则失败');
  }

  async reloadRules() {
    await this.act(async () => {
      await api.reloadRules();
      toasts.success('规则已重新载入');
      await Promise.all([this.loadRules(), this.refreshLive()]);
    }, '载入规则失败');
  }

  async saveSources(next: RuleSource[], done = '规则源已保存'): Promise<boolean> {
    return this.act(async () => {
      const payload = next.map(({ url, enabled, interval_minutes, rule_count }) => ({ url, enabled, interval_minutes, rule_count: rule_count || 0 }));
      await api.saveSources(payload as RuleSource[]);
      toasts.success(done);
      await this.refreshLive();
    }, '保存规则源失败');
  }
}

export const store = new ConsoleStore();
