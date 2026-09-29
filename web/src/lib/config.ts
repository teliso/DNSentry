import type { AccessConfig, Config, DNSCryptConfig, EncryptionConfig, SecureProtocol } from './types';

export const SECURE_PROTOCOLS: SecureProtocol[] = ['dot', 'doh', 'doh3', 'doq'];

const defaultDNSCrypt: DNSCryptConfig = {
  enabled: false,
  listens: [],
  provider_name: 'dnsentry',
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
  dot_listens: [],
  doh_listens: [],
  doh3_listens: [],
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

/** Drops listeners of services that are turned off. */
function finalizeListeners(config: Config): Config {
  const encryption = config.encryption;
  for (const protocol of SECURE_PROTOCOLS) {
    encryption[`${protocol}_listens`] = encryption.enabled ? cleanList(encryption[`${protocol}_listens`]) : [];
  }
  const dnscrypt = encryption.dnscrypt;
  dnscrypt.listens = dnscrypt.enabled ? cleanList(dnscrypt.listens) : [];
  config.dns_listens = cleanList(config.dns_listens);
  return config;
}

/** Fills defaults so the editor always sees complete data. */
export function normalizeConfig(raw: Config): Config {
  const rawEncryption = raw.encryption ?? defaultEncryption;
  const encryption: EncryptionConfig = {
    ...defaultEncryption,
    ...rawEncryption,
    dnscrypt: { ...defaultDNSCrypt, ...rawEncryption.dnscrypt }
  };
  for (const protocol of SECURE_PROTOCOLS) encryption[`${protocol}_listens`] = cleanList(rawEncryption[`${protocol}_listens`]);
  encryption.dnscrypt.listens = cleanList(encryption.dnscrypt.listens);

  return finalizeListeners({
    ...raw,
    dns_listens: cleanList(raw.dns_listens),
    upstreams: cleanList(raw.upstreams),
    fallback_upstreams: cleanList(raw.fallback_upstreams),
    bootstrap_dns: cleanList(raw.bootstrap_dns),
    dnssec_trust_anchors: cleanList(raw.dnssec_trust_anchors),
    local_records: raw.local_records ?? [],
    upstream_routes: (raw.upstream_routes ?? []).map((route) => ({ ...route, domains: [...route.domains], upstreams: [...route.upstreams] })),
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
  copy.upstream_routes = (copy.upstream_routes ?? [])
    .map((route) => ({ ...route, name: route.name?.trim() || undefined, domains: cleanList(route.domains), upstreams: cleanList(route.upstreams) }))
    .filter((route) => route.domains.length > 0 || route.upstreams.length > 0);
  copy.access.allowed_clients = cleanList(copy.access.allowed_clients);
  copy.access.denied_clients = cleanList(copy.access.denied_clients);
  copy.access.rebinding_allow_domains = cleanList(copy.access.rebinding_allow_domains);
  return finalizeListeners(copy);
}

/** Returns a user-facing problem with the config, or null if it can be submitted. */
export function validateConfig(config: Config): string | null {
  if (config.dns_listens.length === 0) return '至少配置一个普通 DNS 监听地址';
  if (config.upstreams.length === 0) return '至少配置一个上游 DNS 服务器';
  for (const [index, route] of config.upstream_routes.entries()) {
    if (route.domains.length === 0 || route.upstreams.length === 0) return `域名分流第 ${index + 1} 条需要同时填写域名和上游`;
  }
  return null;
}
