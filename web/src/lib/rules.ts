import type { Rule, RuleSource } from './types';

/** Canonical text of a rule, matching the server's Entry.Text. */
export function ruleText(rule: Pick<Rule, 'domain' | 'action' | 'ip'>): string {
  if (rule.ip) return `${rule.ip} ${rule.domain}`;
  return rule.action === 'allow' ? `@@||${rule.domain}^` : `||${rule.domain}^`;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** Display name of a rule source: its configured name, else the URL host. */
export function sourceName(url: string | undefined, sources: RuleSource[]): string {
  if (!url) return '本地规则';
  return sources.find((source) => source.url === url)?.name || hostOf(url);
}
