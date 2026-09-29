# VigorDNS

VigorDNS is a Go DNS filtering service with a Svelte management console.

## Run

Install dependencies once, then start the complete service with one command:

```sh
pnpm install
pnpm start
```

管理界面默认只监听 `127.0.0.1:18080`，本机 loopback 请求在未配置 token 时可以直接使用。如果确实需要绑定局域网或公网地址，必须同时设置 `VIGORDNS_ALLOW_PUBLIC_WEB=1` 和非空的 `VIGORDNS_API_TOKEN`；token 只从环境变量读取，不写入 `data/config.yaml`，也不会通过 API 返回。

公开访问示例（PowerShell）：

```powershell
$env:VIGORDNS_ALLOW_PUBLIC_WEB = '1'
$env:VIGORDNS_API_TOKEN = 'replace-with-a-long-random-token'
pnpm start
```

打开 `http://<server-address>:18080/?token=replace-with-a-long-random-token` 可让控制台读取 token 并保存到浏览器 `localStorage`。之后控制台会为 API 请求发送 `Authorization: Bearer <token>`。也可以直接调用 API：

```powershell
$headers = @{ Authorization = "Bearer $env:VIGORDNS_API_TOKEN" }
Invoke-RestMethod http://<server-address>:18080/api/status -Headers $headers
```

公开部署应使用 HTTPS，并通过网络防火墙限制来源；通过 URL 传 token 仅适合首次初始化，因为 URL 可能被浏览器历史或访问日志记录。

`pnpm start` builds the Svelte console and starts the Go DNS service. The console is served at <http://127.0.0.1:18080>. DNS listens on `:15353` by default. These development defaults avoid Windows mDNS port `5353` and common Web port conflicts.

For frontend development with Vite hot reload, run the Go service with `go run .` in one terminal and then run:

```sh
pnpm run dev
```

The DNS listener currently supports UDP and TCP. On Windows, `nslookup` does not accept `IP:port` as its server argument. The project includes a small query client that makes the port explicit:

```powershell
go run ./cmd/vigordns-query -server 127.0.0.1:15353 ai.api.vigorbit.dev
go run ./cmd/vigordns-query -server 127.0.0.1:15353 -type AAAA ai.api.vigorbit.dev
```

A successful query appears in the Web console under 查询日志, or can be inspected with:

```powershell
Invoke-RestMethod http://127.0.0.1:18080/api/logs
```

查询日志默认只保存在内存中。若需要跨重启保留记录，可在 `logging` 中启用异步 JSONL 持久化；每个日期会生成一个 `file-YYYY-MM-DD.jsonl` 文件，启动时会加载当天最近的内存日志条数，并清理超过 `retention_days` 的同前缀文件。`query_log_size` 及所有持久化日志设置的变更均需重启服务后生效。持久化日志包含客户端 IP 和查询域名，应仅在符合隐私、合规和访问控制要求时启用。

Rules are loaded from `data/rules.txt`. Remote rule sources can be configured from 服务设置 or through the API:

```powershell
$source = @(@{ url = 'https://example.com/adguard.txt'; enabled = $true; interval_minutes = 360 })
Invoke-RestMethod http://127.0.0.1:18080/api/sources -Method Put -ContentType 'application/json' -Body ($source | ConvertTo-Json)
```

Sources are fetched once after being added and then refreshed at their configured interval. A failed refresh keeps the last successful rules active.

The resolver also coalesces concurrent requests for the same cache key, skips upstreams after three consecutive failures with exponential cooldown, and exposes primary and fallback upstream health through `/api/status`. `/api/status` returns `dns_listen` as the compatibility primary address and `dns_listens` as the full ordinary DNS address list. `/healthz` reports process liveness and `/readyz` reports whether at least one ordinary DNS listener pair is bound.

```text
||ads.example.com^
@@||trusted.example.com^
0.0.0.0 tracker.example.com
```

Whitelist rules override a matching block rule. Cache behavior is configured in `data/config.yaml` or the Web settings page:

```yaml
cache:
  enabled: true
  size: 4194304
  ttl_min: 0
  ttl_max: 0
  optimistic: false
  optimistic_answer_ttl: 30
  optimistic_max_age: 43200

logging:
  query_log_size: 200
  enabled: false
  file: "data/querylog"
  retention_days: 7

# `enabled` controls optional asynchronous JSONL query-log persistence.
# `file` is a prefix, producing e.g. data/querylog-2026-09-07.jsonl.
# `retention_days` must be between 1 and 365.

dns:
  # `listen` is the compatibility primary address; `listens` is the full list.
  listen: ":15353"
  listens:
    - ":15353"
    - "127.0.0.1:15354"
  upstreams:
    - "1.1.1.1:53"
    - "tls://dns.google:853"
    - "https://cloudflare-dns.com/dns-query"
    - "h3://dns.example/dns-query"
    - "quic://dns.adguard.com:853"
  upstream_mode: "load_balance"
  fallback_upstreams:
    - "tls://backup.example:853"
  bootstrap_dns:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  upstream_timeout_seconds: 4
  enable_dnssec: false
  dnssec_validate: false
  dnssec_trust_anchors: []

encryption:
  enabled: false
  certificate: "data/tls/server.crt"
  private_key: "data/tls/server.key"
  certificate_pem: ""
  private_key_pem: ""
  # The singular fields are compatibility primary addresses.
  dot_listen: ""
  dot_listens: []
  doh_listen: ""
  doh_listens: []
  doh3_listen: ""
  doh3_listens: []
  doq_listen: ""
  doq_listens: []
  dnscrypt:
    enabled: false
    listen: ""
    provider_name: "vigordns"
    private_key: ""
    resolver_secret: ""
    certificate_ttl_hours: 24
```

启用 `encryption.enabled` 后，VigorDNS 会作为入站 DoT、DoH、DoH3 和 DoQ 服务器运行；`encryption.dnscrypt.enabled` 可额外启用 DNSCrypt v2。证书和私钥既可以配置文件路径，也可以在 Web“服务设置”中直接粘贴 PEM 内容；私钥 PEM 不会通过 API 返回。证书、私钥、监听地址、DNSCrypt Provider 和证书有效期可在 Web“服务设置 → 加密 DNS 服务”中配置，保存后需要重启服务。DoH/DoH3 使用 `/dns-query`，DoT/DoQ/DNSCrypt 使用各自配置的监听地址。普通 DNS 的 `dns.listen`/`dns_listen` 与各加密协议的单数 `*_listen` 字段是兼容主地址；`dns.listens`/`dns_listens`、`dot_listens`、`doh_listens`、`doh3_listens`、`doq_listens` 是完整地址列表，每个列表最多 16 个，首项会同步到单数主地址。Web 输入框每行填写一个地址，未启用的加密协议显示为空。DoT、DoQ 默认使用 `:853`，DoH、DoH3 和 DNSCrypt 默认使用 `:443` 作为 placeholder。监听地址为空表示对应协议不监听，启用后可填写 `:端口` 绑定所有地址或填写具体地址；同一协议的多个地址可以使用不同端口。

上游列表支持普通 DNS、DoT（`tls://`）、DoH/HTTP2（`https://`）、DoH3（`h3://host/dns-query`）、DoQ（`quic://`）以及 DNSCrypt v2 的 `sdns://`、`sdns+udp://` 和 `sdns+tcp://` stamp；服务会验证 Provider certificate 后复用 resolver 信息。`fallback_upstreams` 是备用 DNS 列表：仅当主上游无可用响应、超时或返回 `SERVFAIL`/`REFUSED` 时才按列表尝试，不参与主上游的负载均衡、并行或最快 IP 正常请求。`upstream_timeout_seconds` 控制单个上游的连接和查询超时。`upstream_mode` 支持 `load_balance`（轮转并在故障时切换）、`parallel`（并发查询并使用首个有效响应）和 `fastest_addr`（并发查询 A/AAAA 响应，并对最多 16 个公网地址执行 TCP/443 连接测速后将最快地址前置）。后两种模式会将同一个查询发送给多个上游；`fastest_addr` 还会增加地址探测流量，且仅适合确有多线路或 CDN 调度需求的场景。Web 页面“上游 DNS”中的“测试上游”会逐个测试当前文本框里的地址，测试结果不会写入缓存。

`access` 可配置客户端 IP/CIDR 白名单与黑名单、单客户端 QPS 限制、最大并发查询数和 DNS Rebinding 防护；留空白名单、QPS 为 `0` 表示不限制。`local_records` 支持通过 Web DNS 页面或配置文件维护 A、AAAA、CNAME 和 TXT 记录，本地记录优先于缓存和上游。验证状态会在 `/api/status` 和 Web DNS 页面显示；自定义 `dnssec_trust_anchors` 时每行填写一个 DNSKEY。YAML 中的 `cache.enabled` 控制全局缓存开关，`cache.size` 以字节为单位；JSON API 对应字段为 `cache_enabled` 和 `cache_size`。缓存使用 LRU 淘汰。`cache.ttl_min` 和 `cache.ttl_max` 会在写入缓存及首次响应前统一限制 TTL；最大值为 `0` 表示不限制。`cache.optimistic` 开启后，过期响应会以 `cache.optimistic_answer_ttl` 指定的 TTL 返回，并在 `cache.optimistic_max_age` 指定的最大寿命内后台刷新。ECS 请求会按规范化子网建立独立缓存变体；Cookie、NSID、Padding 和未知 EDNS 选项会绕过缓存，避免共享客户端专属响应。Blocking modes are `default` (zero IP), `nxdomain`, `null_ip`, `custom_ip`, and `refused`; the last one uses `blocking_ipv4` and `blocking_ipv6` for custom responses. `blocked_response_ttl` controls how long clients cache filtered responses. `GET /api/status` 和 `GET /api/metrics` expose cache and upstream metrics; `POST /api/cache/clear` clears entries without restarting the service. The current MVP includes DNS forwarding, upstream failover, UDP-to-TCP fallback for truncated responses, an in-memory cache, query logs, minute-level traffic metrics, rule management APIs, and clean listener binding errors.
