# 配置参考

## 配置文件

配置保存在一个 YAML 文件里（默认 `data/config.yaml`，用 `-config` 指定其他路径）。**首次启动如果不存在会自动创建默认配置**，规则文件、日志等数据文件默认放在同一目录。控制台里的所有设置最终都写进这个文件，你也可以直接编辑（保存后需要重启服务，或通过控制台修改以便即时生效）。

带完整注释的参考文件：[`deploy/config.example.yaml`](../deploy/config.example.yaml)，可以用下面的命令校验：

```sh
dnsentry -config /path/to/config.yaml -check
```

- **相对路径**以服务的**工作目录**为基准。
- **改动生效方式**：大多数设置保存后立即生效；标注 `[restart]` 的（监听地址、控制台地址、规则文件路径、查询日志存储、加密 DNS）需要重启，控制台会提示。
- 配置里不包含访问令牌；令牌只从环境变量读取。
- 每次保存都会在配置文件旁的 `history/` 目录记录一个版本（最多 30 个，权限 0600），可以在控制台恢复。

## 默认值一览

| 项目 | 默认值 |
| --- | --- |
| DNS 监听 | `:15353`（UDP + TCP） |
| 控制台监听 | `127.0.0.1:18080` |
| 上游 | `1.1.1.1:53`、`8.8.8.8:53`，负载均衡，超时 4 秒 |
| Bootstrap DNS | `1.1.1.1:53`、`8.8.8.8:53` |
| 拦截响应 | NXDOMAIN，TTL 10 秒 |
| 缓存 | 开启，4 MB，预取与乐观缓存关闭 |
| 私网反向解析 | 开启 |
| 查询日志 | 内存 1000 条，不持久化，持久化时保留 7 天 |
| 访问控制 | 不限制客户端，不限速，最大并发 2048 |
| 加密 DNS | 关闭 |

## 命令行参数

```text
dnsentry [-config data/config.yaml] [-log-level info] [-log-format text]
dnsentry -check         校验配置（含控制台访问的安全要求）后退出
dnsentry -version       输出版本号
dnsentry -healthcheck URL   请求 URL，返回 200 则退出码为 0（用于容器健康检查）
```

| 参数 | 说明 |
| --- | --- |
| `-config` | 配置文件路径，不存在时按默认值创建 |
| `-log-level` | `debug` / `info` / `warn` / `error`，默认 `info` |
| `-log-format` | `text`（默认）或 `json` |

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `DNSENTRY_API_TOKEN` | 控制台 / API 访问令牌。设置后所有 API 请求都需要 `Authorization: Bearer <token>`。不会写入配置文件，也不会通过 API 返回。 |
| `DNSENTRY_ALLOW_PUBLIC_WEB` | 设为 `1` 才允许控制台监听非回环地址（同时必须设置令牌，否则拒绝启动）。 |
| `DNSENTRY_LOG_LEVEL` / `DNSENTRY_LOG_FORMAT` | 对应 `-log-level` / `-log-format`；命令行参数优先。 |
| `DNSENTRY_DNS_LISTEN` / `DNSENTRY_WEB_LISTEN` | 只在**首次生成默认配置**时使用的监听地址，方便容器和服务部署；已有配置文件时不起作用。 |

## 配置项说明

以下按配置文件的结构列出，完整注释见 `deploy/config.example.yaml`。

```yaml
version: 1
dns:
  listens: [":15353"]              # [restart] 普通 DNS 监听地址，最多 16 个，UDP+TCP
  upstreams: ["1.1.1.1:53"]        # 主上游，最多 32 个
  fallback_upstreams: []           # 备用上游
  upstream_mode: load_balance      # load_balance | parallel | fastest_addr
  bootstrap_dns: ["1.1.1.1:53"]    # 解析加密上游域名用的普通 DNS
  upstream_timeout_seconds: 4
  upstream_routes: []              # 域名分流，见 docs/dns.md
  private_reverse: true            # 私网反向解析由本机应答
  block_aaaa: false                # AAAA 查询返回空应答
  blocking_mode: nxdomain          # default | nxdomain | null_ip | custom_ip | refused
  blocking_ipv4: 0.0.0.0           # 仅 custom_ip
  blocking_ipv6: "::"              # 仅 custom_ip
  blocked_response_ttl: 10
  enable_dnssec: false
  dnssec_validate: false
  dnssec_trust_anchors: []
  dnssec_trust_anchor_file: ""
  dnssec_auto_update: false
  local_records: []                # 也可在控制台“本地记录”页维护
web:
  listen: 127.0.0.1:18080          # [restart]
cache:
  enabled: true
  size: 4194304                    # 字节
  ttl_min: 0                       # 秒，0 = 不限制
  ttl_max: 0
  prefetch: false
  optimistic: false
  optimistic_answer_ttl: 30
  optimistic_max_age: 43200
rules:
  local_file: data/rules.txt       # [restart] 本地规则文件；规则源缓存放在同目录 remote/
  sources: []                      # 规则源：url、name、enabled、interval_minutes
access:
  allowed_clients: []              # IP / CIDR，空 = 所有客户端
  denied_clients: []
  client_rate_limit_qps: 0         # 0 = 不限
  max_concurrent_queries: 2048
  rebinding_protection: false
  rebinding_allow_domains: []
logging:
  query_log_size: 1000             # [restart] 内存中保留的条数
  enabled: false                   # [restart] 是否写 JSONL 文件
  file: data/querylog              # [restart] 文件前缀：data/querylog-YYYY-MM-DD.jsonl
  retention_days: 7                # [restart] 1–365
encryption:                        # [restart] 整个加密 DNS 服务
  enabled: false
  certificate: ""
  private_key: ""
  dot_listens: []
  doh_listens: []
  doh3_listens: []
  doq_listens: []
  dnscrypt:
    enabled: false
    listens: []
    provider_name: dnsentry
    private_key: ""                # 空 = 首次启用时自动生成
    resolver_secret: ""            # 同上
    certificate_ttl_hours: 24
```

规则源在配置文件里只保存配置（地址、名称、开关、更新间隔），更新时间、规则数、错误信息等运行状态保存在 `remote/` 缓存里。旧版本的单地址键（`dns.listen`、`dot_listen`、`dnscrypt.listen`）仍然可以读取，会并入对应的列表，但不再写回。

## 通过 API 修改路径的限制

规则文件、查询日志、DNSSEC 信任锚文件、证书和私钥这些路径，通过控制台 / API 修改时只能是**工作目录内的相对路径**（服务会用自己的权限读写这些文件）。需要绝对路径时请直接编辑配置文件。已有的路径值不受影响。
