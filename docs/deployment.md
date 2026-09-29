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
  3. 环境变量 `DNSENTRY_API_TOKEN=<足够长的随机字符串>`。
  缺少任意一个，服务会拒绝启动并说明原因。
- 浏览器打开控制台会提示输入令牌，保存在浏览器的 localStorage 里。也可以用 `http://地址:18080/?token=…` 首次传入（地址栏里的 token 会被立即移除，但可能留在浏览器历史或访问日志里，只建议初次使用）。
- 通过**反向代理**访问时：务必设置令牌，并在代理处终止 HTTPS。本机的反向代理会让远程请求看起来像来自本机，没有令牌就等于没有保护。
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
3. 出问题时：控制台“服务设置 → 配置历史”可以恢复到升级前的配置；二进制回退到旧版本即可。

## 备份与恢复

需要备份的是**配置文件所在的整个目录**（默认 `data/`）：

| 内容 | 位置 |
| --- | --- |
| 配置 | `config.yaml` |
| 配置历史 | `history/`（含完整的配置副本，**包含 DNSCrypt 密钥等敏感内容**） |
| 本地规则 | `rules.txt` |
| 规则源缓存 | `remote/`（可丢弃，丢失后会重新下载） |
| 持久化查询日志 | `querylog-YYYY-MM-DD.jsonl`（若启用；包含客户端地址和域名） |

**这个目录含有密钥，请只让运行服务的用户读取**（配置和历史文件权限已是 0600）。

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
