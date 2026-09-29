# DNSentry

DNSentry 是一个自托管的 DNS 过滤与解析服务，带 Web 管理控制台。它在本地拦截广告、跟踪和恶意域名，把其余请求转发到你选择的上游（支持加密 DNS），并可以对外提供 DoT / DoH / DoH3 / DoQ / DNSCrypt 服务。

- **过滤**：本地规则（AdGuard / hosts / 纯域名语法）+ 远程规则源订阅，下载的列表缓存在磁盘，条件请求增量更新；规则检测可解释任一域名为何被拦截或放行。
- **解析**：域名分流（条件转发）、多上游负载均衡 / 并行，备用上游、自动熔断与恢复，Bootstrap DNS，DNSSEC 验证，本地记录。
- **缓存**：按字节计的分片 LRU，负缓存、TTL 限制、乐观缓存、热门条目预取（`cache.prefetch`），ECS 分片。
- **安全**：客户端白/黑名单、单客户端限速、并发上限、DNS Rebinding 防护；控制台默认只监听本机，公开访问必须配置令牌。
- **可观测**：查询日志（可持久化为 JSONL）、仪表盘、Prometheus 指标、`/healthz` 与 `/readyz`、结构化日志。

## 快速开始

需要 Go 1.26+；从源码构建控制台还需要 Node 22 与 pnpm。

```sh
pnpm install
pnpm start          # 构建控制台并启动服务
```

首次启动会在 `data/` 下生成默认配置 `config.yaml` 与规则文件 `rules.txt`。打开 <http://127.0.0.1:18080> 进入控制台；DNS 默认监听 `:15353`（避开需要特权的 53 端口和 Windows mDNS 的 5353），可以用自带的查询工具测试：

```sh
go run ./cmd/dnsentry-query -server 127.0.0.1:15353 example.com
go run ./cmd/dnsentry-query -server 127.0.0.1:15353 -type AAAA example.com
```

## 部署

### 二进制 + systemd

```sh
make web build VERSION=v1.0.0          # 生成静态链接的 ./dnsentry
sudo install -m 0755 dnsentry /usr/local/bin/
sudo install -m 0644 deploy/dnsentry.service /etc/systemd/system/
sudo systemctl enable --now dnsentry
```

[`deploy/dnsentry.service`](deploy/dnsentry.service) 以动态用户运行、只授予绑定 53 端口所需的能力，并启用了 systemd 的沙箱选项。数据保存在 `/var/lib/dnsentry`，首次启动时 DNS 监听 `:53`。环境变量（如 `DNSENTRY_API_TOKEN`）放在 `/etc/dnsentry/env`。

### Docker

```sh
docker build --build-arg VERSION=v1.0.0 -t dnsentry .
DNSENTRY_API_TOKEN=$(openssl rand -hex 24) docker compose -f deploy/compose.yaml up -d
```

镜像基于 distroless、以非 root 用户运行，数据卷为 `/var/lib/dnsentry`，DNS 监听 53、控制台监听 18080，并带有健康检查。容器内的控制台是“公开”地址，因此必须提供 `DNSENTRY_API_TOKEN`；[`deploy/compose.yaml`](deploy/compose.yaml) 默认只把控制台端口映射到宿主机的 127.0.0.1。

## 运行参数

```text
dnsentry [-config data/config.yaml] [-log-level info] [-log-format text]
dnsentry -check      # 校验配置（含访问安全要求）后退出，适合部署前检查
dnsentry -version
dnsentry -healthcheck http://127.0.0.1:18080/readyz   # 返回 0 表示就绪
```

| 环境变量 | 作用 |
| --- | --- |
| `DNSENTRY_API_TOKEN` | 控制台 / API 访问令牌。设置后所有 API 请求都需要 `Authorization: Bearer <token>`。不会写入配置文件，也不会通过 API 返回。 |
| `DNSENTRY_ALLOW_PUBLIC_WEB` | 设为 `1` 才允许控制台监听非回环地址（同时必须设置令牌）。 |
| `DNSENTRY_LOG_LEVEL` / `DNSENTRY_LOG_FORMAT` | 对应 `-log-level`（debug/info/warn/error）与 `-log-format`（text/json）。 |
| `DNSENTRY_DNS_LISTEN` / `DNSENTRY_WEB_LISTEN` | 仅在首次生成默认配置时使用的监听地址，便于容器与服务部署。 |

服务收到 SIGINT / SIGTERM 后会优雅关闭（最长 10 秒）。

## 配置

所有设置都保存在 YAML 配置文件中，带注释的完整参考见 [`deploy/config.example.yaml`](deploy/config.example.yaml)。大多数设置可以在控制台修改并**立即生效**；监听地址、Web 地址、规则文件路径、查询日志存储和加密 DNS 属于启动时设置，保存后需要重启，控制台会显示提示（`/api/status` 中的 `restart_required`）。每次保存前旧配置会备份为 `config.yaml.bak`，可在“服务设置 → 备份与维护”中一键恢复。配置中的相对路径以服务的工作目录为基准。

### 控制台访问安全

控制台默认只监听 `127.0.0.1:18080`，本机请求无需令牌；本机的写操作要求同源请求，以防跨站请求伪造。需要从其他设备访问时：

```sh
export DNSENTRY_ALLOW_PUBLIC_WEB=1
export DNSENTRY_API_TOKEN='a-long-random-token'
```

并把配置中的 `web.listen` 改为例如 `0.0.0.0:18080`。浏览器打开控制台时会提示输入令牌（也可以用 `?token=` 首次传入，之后保存在浏览器本地）。公开部署请放在 HTTPS 反向代理之后并限制来源。

## 过滤规则

本地规则保存在 `rules.txt`，可在“过滤规则”页逐条增删，或直接编辑整个文件（保留注释，保存后立即生效）：

```text
example.com                 # 拦截该域名及其所有子域名
||ads.example.com^          # AdGuard 语法，同上
@@||trusted.example.com^    # 放行
0.0.0.0 a.example b.example # hosts 语法（0.0.0.0 / 127.0.0.1 / ::），一行可含多个域名
```

以 `#` 或 `!` 开头为注释。带修饰符（`$third-party` 等）、通配符、正则或指向其他地址的 hosts 条目不受支持，会被忽略，保存时控制台会列出这些行。

**优先级**：最具体的域名上的规则生效；同一域名上本地规则优先于规则源，同类规则中放行优先于拦截。过滤规则在缓存和上游之前执行，修改后下一次查询即生效。

**规则源**：在“规则源”页订阅在线列表并设置名称与更新频率。下载的列表缓存在规则文件同目录的 `remote/` 中，重启后立即生效；到期后使用 `ETag` / `Last-Modified` 条件请求。下载失败时继续使用上一版并在 10 分钟后重试；停用会立即撤下规则并保留缓存，删除会一并清除缓存。

**排查**：“过滤规则 → 规则检测”显示某个域名命中的规则及来源；查询日志中每条拦截/放行都附带所依据的规则，并可一键放行或拦截。

## 解析与上游

上游支持普通 DNS（`1.1.1.1:53`）、DoT（`tls://host:853`）、DoH（`https://host/dns-query`）、DoH3（`h3://host/dns-query`）、DoQ（`quic://host:853`）和 DNSCrypt（`sdns://`）。分发策略（旧版本的 `fastest_addr` 已移除，读取到时按 `load_balance` 处理）：

- `load_balance`：按健康状态轮转，额外流量最少（默认）。
- `parallel`：同时询问多个上游，取首个有效响应。

连续失败 3 次的上游会按指数退避暂时跳过；`fallback_upstreams` 只在主上游全部失败、超时或返回 SERVFAIL/REFUSED 时使用。并发的相同查询会合并为一次上游请求。“DNS 设置 → 测试上游”可逐个测试地址（结果不写入缓存）。

**域名分流**：在“DNS 设置 → 域名分流”里让指定域名（含子域名）使用专属上游，最具体的域名优先，例如：

```yaml
dns:
  upstream_routes:
    - name: 公司内网
      domains: [corp.example.com, 10.in-addr.arpa]
      upstreams: ["10.0.0.1:53"]
```

分流的域名只会发给它的专属上游，失败时**不会**回退到默认上游或备用上游（以免把内部域名泄露给公网解析器），客户端得到 SERVFAIL。分流域名视为可信，不受 DNS Rebinding 防护和本地 DNSSEC 验证影响。

**本地记录**（A / AAAA / CNAME / TXT）在“本地记录”页维护，优先于缓存和上游。A / AAAA 记录会自动生成对应的 PTR 记录（反向解析）。`dns.private_reverse`（默认开启）让私网地址（10.x、172.16–31.x、192.168.x、169.254.x、127.x、fc00::/7、fe80::/10）的反向查询由本机应答：匹配本地记录的返回主机名，其余返回 NXDOMAIN，不再发往公网上游；已配置分流的反向区除外。`dns.block_aaaa` 让 AAAA 查询直接返回空应答，适合没有 IPv6 出口的网络。

**DNSSEC**：`enable_dnssec` 向上游请求签名数据，`dnssec_validate` 在本地校验签名链（内置 IANA 根信任锚，或自定义 / 受控文件，文件变更自动热重载）。

## 加密 DNS 服务

在“服务设置 → 加密 DNS”中启用后，DNSentry 作为 DoT、DoH（`/dns-query`）、DoH3 与 DoQ 服务器运行；证书与私钥可填写路径或直接粘贴 PEM（私钥不会通过 API 返回）。DNSCrypt v2 可单独启用，密钥在首次启用时生成，运行后控制台显示可复制的客户端 stamp。每种协议最多 16 个监听地址。

## 可观测性

- **查询日志**：内存中保留最近 `logging.query_log_size` 条；`logging.enabled` 可额外按天写入 `<file>-YYYY-MM-DD.jsonl` 并按 `retention_days` 清理。持久化日志包含客户端 IP 与域名，请按隐私与合规要求启用。
- **指标**：`GET /api/metrics` 输出 Prometheus 格式的查询、拦截、安全、缓存与上游指标。
- **健康检查**：`/healthz` 表示进程存活，`/readyz` 表示至少一个 DNS 监听已就绪（均无需令牌）。

## HTTP API

所有接口位于 `/api` 下，返回 JSON。

| 方法与路径 | 说明 |
| --- | --- |
| `GET /status` | 运行状态、统计、上游健康、规则源状态、版本 |
| `GET /metrics` | Prometheus 指标 |
| `GET` / `PUT /config`，`POST /config/restore` | 读取、保存（立即应用可热更新部分）、恢复上一版配置 |
| `POST /cache/clear` | 清空 DNS 缓存 |
| `POST /upstreams/test` | 测试上游 `{"upstreams": [...]}` |
| `GET /logs?search=&action=&offset=&limit=` | 查询日志（分页） |
| `GET /rules?search=&action=&source=&offset=&limit=` | 规则（分页；`source` 为 `local` 或规则源 URL） |
| `POST` / `DELETE /rules` | 添加 `{"domain","action"}` / 删除（`?domain=&action=`）本地规则 |
| `GET /rules/check?domain=` | 解释域名命中的规则 |
| `GET` / `PUT /rules/local` | 读取 / 整体替换 `rules.txt` 文本 |
| `POST /reload` | 从磁盘重新载入 `rules.txt` |
| `GET` / `PUT /sources`，`POST /sources/refresh` | 规则源列表、保存、立即更新（`{"url": ""}` 表示全部） |

示例：

```sh
curl -H "Authorization: Bearer $DNSENTRY_API_TOKEN" http://127.0.0.1:18080/api/status
```

## 开发

```sh
go run ./cmd/dnsentry     # 终端 1：后端
pnpm dev                  # 终端 2：Vite 热更新控制台，/api 代理到 127.0.0.1:18080
make test                 # go vet、go test -race、svelte-check
```

`web/dist` 通过 `go:embed` 打包进二进制并提交在仓库中，因此 `go install` / `go build` 无需 Node。修改前端后请运行 `pnpm build` 并提交 `web/dist`（CI 会检查）。

```text
cmd/dnsentry/         服务入口与命令行参数
cmd/dnsentry-query/   指定端口的 DNS 查询小工具
internal/app/         DNS 服务、上游策略、加密 DNS、DNSSEC、配置与 HTTP API
internal/rules/       规则解析与匹配、本地规则文件、远程规则源（下载、磁盘缓存、定时更新）
internal/querylog/    查询日志、仪表盘聚合与 JSONL 持久化
internal/cache/       分片 LRU DNS 缓存
internal/dnsname/     域名规范化与校验
internal/fsutil/      原子写文件
internal/buildinfo/   版本信息
web/                  Svelte 5 + TypeScript 控制台（源码 web/src，构建产物 web/dist）
deploy/               配置参考、systemd 单元、Docker Compose
```

控制台源码按职责划分：`lib/`（API 客户端、类型、状态、路由）、`components/`（通用组件）、`sections/`（设置分区）、`pages/`（页面）。
