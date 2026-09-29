# DNSentry

自托管的 DNS 过滤与解析服务，带 Web 管理控制台。在本地拦截广告、跟踪和恶意域名，其余请求转发到你选择的上游（支持加密 DNS），并可以对外提供 DoT / DoH / DoH3 / DoQ / DNSCrypt 服务。

![仪表盘](docs/images/dashboard.png)

## 特点

- **过滤规则**：本地规则（AdGuard / hosts / 纯域名语法）＋远程规则源订阅；下载的列表缓存在磁盘，重启后立即生效；**规则检测**能解释任一域名为何被拦截或放行。
- **解析**：多上游（普通 DNS、DoT、DoH、DoH3、DoQ、DNSCrypt）、负载均衡 / 并行、备用上游、自动熔断与恢复、**按域名分流**（条件转发）、本地记录、DNSSEC 验证。
- **缓存**：分片 LRU，负缓存、TTL 限制、乐观缓存、热门条目预取。
- **可观测**：仪表盘（流量趋势、上游 30 分钟延迟、最慢与失败域名）、查询日志（可持久化）、Prometheus 指标、全局健康提醒、**配置变更历史**。
- **安全**：控制台默认只监听本机，公开访问必须配置令牌；客户端白/黑名单、限速、并发上限、DNS Rebinding 防护。
- **易部署**：单个静态二进制（内嵌控制台），首次启动自动生成配置；提供 systemd 单元、Docker 镜像和 Compose 文件。

## 快速开始

需要 Go 1.26+；从源码运行控制台还需要 Node 22 与 pnpm。

```sh
git clone https://github.com/teliso/DNSentry.git
cd DNSentry
pnpm install
pnpm start
```

首次启动会在 `data/` 下生成默认配置和规则文件。打开 <http://127.0.0.1:18080> 进入控制台；DNS 默认监听 `:15353`，用自带的小工具测试：

```sh
go run ./cmd/dnsentry-query -server 127.0.0.1:15353 example.com
```

想让家里的设备真正用上它，请看 [入门指南](docs/getting-started.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [入门指南](docs/getting-started.md) | 安装、第一次启动、让设备使用 DNSentry、验证是否生效 |
| [控制台使用指南](docs/console.md) | 每个页面能做什么、常见操作怎么做 |
| [过滤规则](docs/filtering.md) | 规则语法、优先级、规则源、规则检测 |
| [解析与加密 DNS](docs/dns.md) | 上游、分流、缓存、DNSSEC、本地记录、对外提供加密 DNS |
| [配置参考](docs/configuration.md) | 配置文件、命令行参数、环境变量 |
| [部署与运维](docs/deployment.md) | 二进制 / systemd / Docker、升级、备份、监控 |
| [强制所有设备使用 DNSentry](docs/enforce-dns.md) | 路由器上的 DHCP、重定向与防绕过 |
| [HTTP API](docs/api.md) | 全部接口与示例 |
| [故障排查](docs/troubleshooting.md) | 常见问题与排查步骤 |
| [开发指南](docs/development.md) | 目录结构、构建、测试、发布 |
| [SECURITY.md](SECURITY.md) | 威胁模型与漏洞报告 |

## 许可证

Copyright (C) 2026 Teliso Young

DNSentry 以 [GNU Affero 通用公共许可证 第 3 版（AGPL-3.0）](LICENSE)发布。简单说：你可以自由使用、修改和分发它；如果你修改后通过网络向他人提供服务，也必须向这些用户提供你修改后的源代码。
