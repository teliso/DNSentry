import type { AccessConfig, Config, DNSCryptConfig, EncryptionConfig, SecureProtocol } from './types';

export const SECURE_PROTOCOLS: SecureProtocol[] = ['dot', 'doh', 'doh3', 'doq'];

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

const defaultAccess: AccessConfig = {
  allowed_clients: [],
  denied_clients: [],
  client_rate_limit_qps: 0,
  max_concurrent_queries: 2048,
  rebinding_protection: false,
  rebinding_allow_domains: []
};

export function cleanList(values: readonly string[] | null | undefined): string[] {
  return (values ?? []).map((value) => value.trim()).filter(Boolean);
}

/** The API exposes a legacy singular "primary" address next to the full list. */
function mergeLegacy(list: readonly string[] | undefined, legacy: string | undefined): string[] {
  const values = cleanList(list);
  return values.length > 0 ? values : cleanList(legacy ? [legacy] : []);
}

/** Recomputes every singular "primary" field from its list and drops listeners of disabled services. */
function finalizeListeners(config: Config): Config {
  const encryption = config.encryption;
  for (const protocol of SECURE_PROTOCOLS) {
    const list = encryption.enabled ? cleanList(encryption[`${protocol}_listens`]) : [];
    encryption[`${protocol}_listens`] = list;
    encryption[`${protocol}_listen`] = list[0] ?? '';
  }
  const dnscrypt = encryption.dnscrypt;
  dnscrypt.listens = dnscrypt.enabled ? cleanList(dnscrypt.listens) : [];
  dnscrypt.listen = dnscrypt.listens[0] ?? '';
  config.dns_listens = cleanList(config.dns_listens);
  config.dns_listen = config.dns_listens[0] ?? '';
  return config;
}

/** Fills defaults and reconciles legacy fields so the editor always sees complete data. */
export function normalizeConfig(raw: Config): Config {
  const rawEncryption = raw.encryption ?? defaultEncryption;
  const encryption: EncryptionConfig = {
    ...defaultEncryption,
    ...rawEncryption,
    dnscrypt: { ...defaultDNSCrypt, ...rawEncryption.dnscrypt }
  };
  for (const protocol of SECURE_PROTOCOLS) {
    encryption[`${protocol}_listens`] = mergeLegacy(rawEncryption[`${protocol}_listens`], rawEncryption[`${protocol}_listen`]);
  }
  encryption.dnscrypt.listens = mergeLegacy(encryption.dnscrypt.listens, encryption.dnscrypt.listen);

  return finalizeListeners({
    ...raw,
    dns_listens: mergeLegacy(raw.dns_listens, raw.dns_listen),
    upstreams: cleanList(raw.upstreams),
    fallback_upstreams: cleanList(raw.fallback_upstreams),
    bootstrap_dns: cleanList(raw.bootstrap_dns),
    dnssec_trust_anchors: cleanList(raw.dnssec_trust_anchors),
    local_records: raw.local_records ?? [],
    access: {
      ...defaultAccess,
      ...raw.access,
      allowed_clients: cleanList(raw.access?.allowed_clients),
      denied_clients: cleanList(raw.access?.denied_clients),
      rebinding_allow_domains: cleanList(raw.access?.rebinding_allow_domains)
    },
    encryption
  });
}

/** Produces the payload sent to PUT /api/config (also used to detect unsaved edits). */
export function serializeConfig(config: Config): Config {
  const copy = JSON.parse(JSON.stringify(config)) as Config; // also unwraps Svelte proxies
  copy.upstreams = cleanList(copy.upstreams);
  copy.fallback_upstreams = cleanList(copy.fallback_upstreams);
  copy.bootstrap_dns = cleanList(copy.bootstrap_dns);
  copy.dnssec_trust_anchors = cleanList(copy.dnssec_trust_anchors);
  copy.access.allowed_clients = cleanList(copy.access.allowed_clients);
  copy.access.denied_clients = cleanList(copy.access.denied_clients);
  copy.access.rebinding_allow_domains = cleanList(copy.access.rebinding_allow_domains);
  return finalizeListeners(copy);
}

/** Returns a user-facing problem with the config, or null if it can be submitted. */
export function validateConfig(config: Config): string | null {
  if (config.dns_listens.length === 0) return '至少配置一个普通 DNS 监听地址';
  if (config.upstreams.length === 0) return '至少配置一个上游 DNS 服务器';
  return null;
}
