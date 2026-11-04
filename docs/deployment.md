# 部署与运维

## 运行方式

DNSentry 是单个静态二进制，控制台已内嵌，运行时不需要 Node 或其他文件。数据（配置、规则、缓存的规则源、日志）都放在**配置文件所在的目录**。

### 二进制

从 GitHub Releases 下载对应平台的压缩包（含二进制、许可证、README 和 `deploy/`），也可以自己构建：

```sh
make web build VERSION=v1.0.0      # 生成 ./dnsentry
./dnsentry -version
```

### systemd（Linux 推荐）

```sh
sudo install -m 0755 dnsentry /usr/local/bin/
sudo install -m 0644 deploy/dnsentry.service /etc/systemd/system/
sudo systemctl enable --now dnsentry
journalctl -u dnsentry -f          # 查看日志
```

[`deploy/dnsentry.service`](../deploy/dnsentry.service) 的要点：

- 以**动态用户**运行，只授予绑定 53 端口所需的能力（`CAP_NET_BIND_SERVICE`），并启用 systemd 的沙箱选项。
- 数据在 `/var/lib/dnsentry`（配置 `/var/lib/dnsentry/config.yaml`），首次启动时 DNS 监听 `:53`。
- 环境变量（如 `DNSENTRY_API_TOKEN`）写在 `/etc/dnsentry/env`，每行一个 `KEY=value`。
- 异常退出后 5 秒自动重启。

### Docker

```sh
docker build --build-arg VERSION=v1.0.0 -t dnsentry .
DNSENTRY_API_TOKEN=$(openssl rand -hex 24) docker compose -f deploy/compose.yaml up -d
```

- 镜像基于 distroless，以非 root 用户运行，数据卷为 `/var/lib/dnsentry`，暴露 53（UDP/TCP）和 18080。
- 容器内控制台监听在 `:18080`，属于“公开”地址，所以**必须提供 `DNSENTRY_API_TOKEN`**；`compose.yaml` 默认只把控制台端口映射到宿主机的 127.0.0.1。
- 自带健康检查（请求 `/readyz`）。
- **想在容器里看到局域网中各设备的真实来源地址**时，DNS 端口必须直接暴露（`-p 53:53/udp`）或使用主机网络；经过 Docker 的 NAT 端口映射通常仍能保留客户端地址，但通过其他代理转发就不一定。

## 访问控制台

- 默认只监听 `127.0.0.1:18080`，只能在本机用 `http://localhost:18080` 或 `http://127.0.0.1:18080` 打开。
- **要从其他设备访问**，三件事缺一不可：
  1. 配置文件里把 `web.listen` 改成例如 `0.0.0.0:18080`（或用首次配置的 `DNSENTRY_WEB_LISTEN`）；
  2. 环境变量 `DNSENTRY_ALLOW_PUBLIC_WEB=1`；
  3. 一种登录方式（任选其一，也可以两个都用）：
     - **控制台密码（推荐给人用）**：先在本机打开控制台，到“设置 → 控制台登录”设置用户名和密码，再把监听地址改成公开的；
     - **环境变量 `DNSENTRY_API_TOKEN=<足够长的随机字符串>`**（适合容器和脚本）。
  缺少任意一个，服务会拒绝启动并说明原因。
- **密码登录**：设置密码后，包括本机在内打开控制台都要先登录；登录状态保存在浏览器的 HttpOnly Cookie 里（7 天，重启服务后失效）。密码以 bcrypt 哈希保存在配置文件同目录的 `auth.json`（权限 0600）。登录失败同样按来源限制：连续 10 次错误封锁到这一分钟结束。**在配置文件里直接设置密码**（类似 AdGuard Home，可以使用少于 8 位的短密码）：停止服务，在 `config.yaml` 里加入

  ```yaml
  web:
    auth:
      username: admin
      password: abc        # 明文，或者 bcrypt 哈希（$2a$… / $2b$…）
  ```

  下次启动时程序把它转成哈希写入 `auth.json`，并立即从配置文件中删除这一段，明文不会留在磁盘上，也不会进入配置历史。控制台里设置密码仍然要求至少 8 位。**忘记密码**：停止服务，删除 `auth.json`，重新启动即可（之后控制台回到“只能本机访问”）。
- **令牌**：脚本和监控用 `Authorization: Bearer <token>` 访问 API；浏览器里没设密码时，打开控制台会提示输入令牌，保存在浏览器的 localStorage 里。也可以用 `http://地址:18080/?token=…` 首次传入（地址栏里的 token 会被立即移除，但可能留在浏览器历史或访问日志里，只建议初次使用）。
- **HTTPS**：控制台默认是明文 HTTP。到“设置 → 网络与访问 → 控制台 HTTPS”打开开关并重启后，控制台改用 HTTPS（地址变成 `https://…`，原来的 `http://` 地址不再可用）。证书有三种来源：
  - **自动生成（自签名）**：保存在配置文件同目录（`web-tls.crt`、`web-tls.key`，含本机主机名和当前网卡地址，有效期 825 天，临近到期自动更新）。浏览器会提示“不安全”，请对照控制台里显示的 SHA-256 指纹后选择继续；每次重新生成证书都会换指纹。
  - **复用加密 DNS 的证书**：与 DoH / DoT 共用同一张证书（路径或粘贴的 PEM 都行），不用重复配置。
  - **单独指定证书**：填写证书（可含中间证书链）和私钥的 PEM 路径，例如 mkcert 或 Let's Encrypt 的。证书文件更新（续期）后约 10 秒内自动生效，不需要重启。
- **绑定域名（`server_name`）**：证书只看你打开控制台时用的**主机名**，和端口、路径无关，所以 `https://dns.example.com/dns-query`（DoH）和 `https://dns.example.com:18080/`（控制台）可以共用同一张证书而不警告——前提是这个域名在你的设备上能解析到本机（局域网里可在“DNS → 本地记录”加一条）。填了绑定域名后：自动生成的证书会包含它；其他来源的证书如果不包含它，设置页会给出警告并列出证书实际适用的名称。绑定域名不会限制访问方式，仍可用 IP 打开（只是会有证书不匹配的提示）。
- 有 HTTPS 时，登录 Cookie 自动带 `Secure` 标记。容器的健康检查（`-healthcheck`）对本机地址会自动兼容 HTTPS。
- 通过**反向代理**访问时：务必设置密码或令牌，并在代理处终止 HTTPS（或者直接用上面的控制台 HTTPS）。本机的反向代理会让远程请求看起来像来自本机，没有令牌就等于没有保护。
- 令牌校验连续失败 10 次，该来源会被封锁到这一分钟结束。

详细的安全模型见 [SECURITY.md](../SECURITY.md)。

## 监听 53 端口

| 方式 | 说明 |
| --- | --- |
| systemd 单元 | 已配置 `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| `setcap` | `sudo setcap 'cap_net_bind_service=+ep' ./dnsentry` |
| Docker | 容器内以 `:53` 监听，映射宿主机 53 |
| 端口转换 | DNSentry 监听 `:15353`，用防火墙把 53 转发过去 |

**53 端口被占用**：很多 Linux 发行版的 `systemd-resolved` 占用了 `127.0.0.53:53`，如果 DNSentry 监听 `:53`（所有地址）会冲突。解决办法：监听具体的局域网地址（例如 `192.168.1.2:53`），或者在 `/etc/systemd/resolved.conf` 里设置 `DNSStubListener=no` 后重启 `systemd-resolved`。

## 升级

1. 停止服务，替换二进制（或拉取新镜像）。
2. 启动。配置文件向前兼容；旧版本的单地址键（`dns.listen` 等）仍然可读取。
3. 出问题时：控制台“设置 → 维护”里的配置历史可以恢复到升级前的配置；二进制回退到旧版本即可。

## 备份与恢复

需要备份的是**配置文件所在的整个目录**（默认 `data/`）：

| 内容 | 位置 |
| --- | --- |
| 配置 | `config.yaml` |
| 配置历史 | `history/`（含完整的配置副本，**包含 DNSCrypt 密钥等敏感内容**） |
| 本地规则 | `rules.txt` |
| 控制台 HTTPS 证书 | `web-tls.crt`、`web-tls.key`（自动生成的自签名证书；私钥敏感，丢失会重新生成） |
| 控制台登录 | `auth.json`（用户名与密码哈希；敏感，丢失后控制台回到“只能本机访问”） |
| 统计数据 | `stats.json`（每小时的查询数和拦截数，最多 90 天，不含域名和客户端；丢失只会让历史图表清零） |
| 规则源缓存 | `remote/`（可丢弃，丢失后会重新下载） |
| 持久化查询日志 | `querylog-YYYY-MM-DD.jsonl`（若启用；包含客户端地址和域名） |

**这个目录含有密钥，请只让运行服务的用户读取**（配置和历史文件权限已是 0600）。

## 通知

控制台“设置 → 通知”里添加 Webhook 后，DNSentry 会在下面这些情况主动发消息，不用一直开着控制台：

| 事件 | 触发条件 |
| --- | --- |
| 上游故障 | 所有默认上游都没有响应；或某条域名分流的上游全部没有响应 |
| 规则源更新失败 | 规则源超过一天（或两个更新周期，取较长者）没有更新成功 |

- 问题要**持续约 1 分钟**（连续两次检查，每 30 秒一次）才会通知，瞬时的抖动不会打扰你；问题消失后再发一条“已恢复”。同一个问题不会重复通知。
- 发送失败会重试 3 次（2 秒、4 秒间隔），仍失败只在日志里记一条警告，不影响服务。
- **消息格式**：
  - `json`（默认）：`{"event","id","title","message","time","instance","version"}`，并额外带有 `text`（Slack、Mattermost）、`content`（Discord）、`title`/`message`（Gotify），这些服务可以直接填它们的 Webhook 地址。
  - `plain`（纯文本，适合 [ntfy](https://ntfy.sh)）：请求体是消息正文，标题放在 `Title` 头里，`Tags` 头标记类型。
- 服务器**主动访问**你填的地址（和规则源、上游测试一样），不会跟随重定向。地址里通常带密钥，请像密码一样保管；它保存在配置文件里，也会出现在配置导出和历史版本中。
- 配置文件里的写法：

  ```yaml
  notifications:
    events: [upstream, rule_source]   # 留空 = 全部
    webhooks:
      - { name: 手机, url: "https://ntfy.sh/my-dnsentry", format: plain, enabled: true }
  ```

## 监控

- **健康检查**（无需令牌）：`GET /healthz`（进程存活）、`GET /readyz`（至少一个 DNS 监听已就绪）。
- **Prometheus 指标**：`GET /api/metrics`（需要令牌时带 `Authorization` 头）。

  | 指标 | 类型 | 说明 |
  | --- | --- | --- |
  | `dnsentry_dns_queries_total` / `dnsentry_dns_blocked_total` | counter | 查询总数 / 拦截数 |
  | `dnsentry_dns_access_denied_total`、`_rate_limited_total`、`_overloaded_total`、`_rebinding_blocked_total` | counter | 被访问控制、限速、过载、Rebinding 防护拒绝的数量 |
  | `dnsentry_cache_entries`、`_used_bytes`、`_max_bytes` | gauge | 缓存条目与容量 |
  | `dnsentry_cache_hits_total`、`_misses_total`、`_stale_hits_total`、`_bypasses_total`、`_evictions_total`、`_refresh_success_total`、`_refresh_failure_total`、`_prefetches_total` | counter | 缓存统计 |
  | `dnsentry_cache_hit_rate` | gauge | 命中率（0–1） |
  | `dnsentry_upstream_requests_total`、`_successes_total`、`_consecutive_failures`、`_latency_milliseconds` | counter / gauge | 每个上游（标签 `role`、`upstream`） |

  Prometheus 抓取配置示例：

  ```yaml
  scrape_configs:
    - job_name: dnsentry
      metrics_path: /api/metrics
      authorization: { credentials: "<token>" }
      static_configs: [{ targets: ["192.168.1.2:18080"] }]
  ```
- **日志**：结构化日志输出到标准错误，`-log-format json` 便于日志系统采集。查询日志见控制台，或启用持久化后按天写入 JSONL 文件。

## 关闭

收到 SIGINT / SIGTERM 后会优雅关闭（最长 10 秒）：停止接收新请求，等待在途请求完成，再退出。
