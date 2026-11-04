import { api, APIError, initToken, setToken, setUnauthorizedHandler } from './api';
import { normalizeConfig, serializeConfig, validateConfig } from './config';
import { toasts } from './toast.svelte';
import type { AuthStatus, Config, LocalRecord, LocalSummary, Rule, RuleAction, RuleSource, Status, UpstreamTest } from './types';

const POLL_INTERVAL_MS = 10_000;

function messageOf(cause: unknown, fallback: string): string {
  if (cause instanceof APIError) return cause.message;
  if (cause instanceof TypeError) return '无法连接到 DNSentry 服务';
  return cause instanceof Error ? cause.message : fallback;
}

/** Client-side state of the console: live data, the saved config and the editable draft. */
class ConsoleStore {
  status = $state.raw<Status | null>(null);
  sources = $state.raw<RuleSource[]>([]);
  /** Bumped after every rule change so rule views know to reload. */
  rulesVersion = $state(0);
  /** Bumped when the saved configuration changes so the history view reloads. */
  configVersion = $state(0);
  /** Source filter requested by another page (e.g. "查看规则" on a source). */
  ruleSourceFilter = $state('');
  online = $state(false);
  busy = $state(false);
  tokenRequired = $state(false);
  /** The console has a password and this browser is not signed in. */
  loginRequired = $state(false);
  auth = $state.raw<AuthStatus | null>(null);

  /** Config as last returned by the server. */
  saved = $state.raw<Config | null>(null);
  /** Editable copy bound to the settings forms. */
  draft = $state<Config | null>(null);

  dirty = $derived(
    this.draft !== null && this.saved !== null && JSON.stringify(serializeConfig(this.draft)) !== JSON.stringify(serializeConfig(this.saved))
  );


  async start() {
    initToken();
    setUnauthorizedHandler(() => void this.askForCredentials());
    await this.loadAuth();
    await Promise.all([this.refreshLive(), this.loadConfig()]);
    window.setInterval(() => {
      if (!document.hidden) void this.refreshLive();
    }, POLL_INTERVAL_MS);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) void this.refreshLive();
    });
  }

  async loadAuth() {
    try {
      this.auth = await api.authStatus();
    } catch {
      /* the regular poll reports connection problems */
    }
  }

  /** A request was refused: show the sign-in form if the console has a password, else the token dialog. */
  private async askForCredentials() {
    await this.loadAuth();
    if (this.auth?.configured) this.loginRequired = true;
    else this.tokenRequired = true;
  }

  async signIn(username: string, password: string): Promise<boolean> {
    try {
      this.auth = await api.login(username, password);
    } catch (cause) {
      toasts.error(messageOf(cause, '登录失败'));
      return false;
    }
    this.loginRequired = false;
    await Promise.all([this.refreshLive(), this.loadConfig()]);
    return true;
  }

  async signOut() {
    await this.act(async () => {
      await api.logout();
      this.auth = await api.authStatus();
      this.status = null;
      this.saved = null;
      this.draft = null;
      this.loginRequired = true;
    }, '退出失败');
  }

  /** Sets, changes (current password required) or removes the console password. */
  async changeLogin(change: { username: string; password: string; current: string } | { remove: true; current: string }): Promise<boolean> {
    return this.act(async () => {
      this.auth = 'remove' in change ? await api.removeLogin(change.current) : await api.setLogin(change.username, change.password, change.current);
      toasts.success('remove' in change ? '控制台登录已关闭' : '控制台登录已保存');
    }, '保存登录设置失败');
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
      const status = await api.status();
      this.status = status;
      this.setSources(status.rule_sources ?? []);
      this.online = true;
      this.tokenRequired = false;
    } catch (cause) {
      if (this.online) toasts.error(messageOf(cause, '无法连接到 DNSentry 服务'));
      this.online = false;
    }
  }

  async submitToken(token: string) {
    setToken(token);
    this.tokenRequired = false;
    this.loginRequired = false;
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

  /** PUT /config and POST /config/restore apply runtime settings at once; startup-only ones wait for a restart. */
  private async commitConfig(call: () => Promise<Config>, done: string, failure: string) {
    await this.act(async () => {
      this.adopt(await call());
      this.configVersion++;
      await this.refreshLive();
      if (this.status?.restart_required) toasts.info(`${done}，部分设置需要重启服务后生效`);
      else toasts.success(done);
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
    await this.commitConfig(() => api.saveConfig(payload), '配置已保存', '保存配置失败');
  }

  async importConfig(yaml: string) {
    await this.commitConfig(() => api.importConfig(yaml), '配置已导入', '导入配置失败');
  }

  async restoreConfig(id?: string) {
    await this.commitConfig(() => api.restoreConfig(id), '配置已恢复', '恢复配置失败');
  }

  /**
   * Saves local records immediately, based on the saved configuration so that
   * unrelated unsaved edits in the settings pages are neither sent nor lost.
   */
  async saveLocalRecords(records: LocalRecord[], done: string): Promise<boolean> {
    if (!this.saved) return false;
    const payload = serializeConfig({ ...this.saved, local_records: records });
    return this.act(async () => {
      const result = normalizeConfig(await api.saveConfig(payload));
      this.saved = result;
      if (this.draft) this.draft.local_records = JSON.parse(JSON.stringify(result.local_records));
      this.configVersion++;
      toasts.success(done);
    }, '保存本地记录失败');
  }

  /** Pauses filtering for `minutes` (0 = until resumed) or turns it back on. */
  async setProtection(enabled: boolean, minutes = 0) {
    await this.act(async () => {
      await api.setProtection(enabled, minutes);
      await this.refreshLive();
      toasts.success(enabled ? '过滤已恢复' : minutes ? `过滤已暂停 ${minutes >= 60 ? `${minutes / 60} 小时` : `${minutes} 分钟`}` : '过滤已暂停');
    }, '切换过滤失败');
  }

  async clearCache() {
    await this.act(async () => {
      await api.clearCache();
      toasts.success('DNS 缓存已清空');
      await this.refreshLive();
    }, '清空缓存失败');
  }

  async clearLogs() {
    await this.act(async () => {
      await api.clearLogs();
      toasts.success('内存中的查询日志已清空');
      await this.refreshLive();
    }, '清空日志失败');
  }

  async testUpstreams(addresses: string[]): Promise<UpstreamTest[] | null> {
    let result: UpstreamTest[] | null = null;
    await this.act(async () => {
      result = await api.testUpstreams(addresses);
    }, '上游测试失败');
    return result;
  }

  private rulesChanged() {
    this.rulesVersion++;
    void this.refreshLive();
  }

  async addRule(domain: string, action: RuleAction): Promise<boolean> {
    return this.act(async () => {
      const rule = await api.addRule(domain, action);
      toasts.success(`已添加${rule.action === 'allow' ? '放行' : '拦截'}规则 ${rule.domain}`);
      this.rulesChanged();
    }, '添加规则失败');
  }

  async removeRule(rule: Pick<Rule, 'domain' | 'action'>) {
    await this.act(async () => {
      await api.deleteRule(rule);
      toasts.success('规则已删除');
      this.rulesChanged();
    }, '删除规则失败');
  }

  async saveLocalRules(text: string): Promise<LocalSummary | null> {
    let summary: LocalSummary | null = null;
    await this.act(async () => {
      summary = await api.saveLocalRules(text);
      this.rulesChanged();
    }, '保存规则文件失败');
    return summary;
  }

  async reloadRules() {
    await this.act(async () => {
      await api.reloadRules();
      toasts.success('已从磁盘重新载入本地规则');
      this.rulesChanged();
    }, '载入规则失败');
  }

  private sourcePoll = 0;

  /** Adopts a source list and polls quickly while any source is downloading. */
  private setSources(sources: RuleSource[]) {
    const wasUpdating = this.sources.some((source) => source.updating);
    this.sources = sources;
    const updating = sources.some((source) => source.updating);
    if (wasUpdating && !updating) this.rulesChanged();
    if (updating && !this.sourcePoll) {
      this.sourcePoll = window.setTimeout(async () => {
        this.sourcePoll = 0;
        try {
          this.setSources(await api.sources());
        } catch {
          /* the regular poll reports connection problems */
        }
      }, 1500);
    }
  }

  async refreshSources(url = ''): Promise<boolean> {
    return this.act(async () => {
      this.setSources(await api.refreshSources(url));
      toasts.info(url ? '正在更新规则源' : '正在更新全部规则源');
    }, '更新规则源失败');
  }

  async saveSources(next: RuleSource[], done = '规则源已保存'): Promise<boolean> {
    return this.act(async () => {
      const payload = next.map(({ url, name, enabled, interval_minutes }) => ({ url, name, enabled, interval_minutes }));
      this.setSources(await api.saveSources(payload));
      this.configVersion++;
      toasts.success(done);
      this.rulesChanged();
    }, '保存规则源失败');
  }
}

export const store = new ConsoleStore();
