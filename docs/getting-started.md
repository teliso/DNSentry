# 入门指南

这份指南带你从零开始：装好 DNSentry，让家里的设备用上它，并确认它在工作。

## 1. 安装

任选一种方式，细节见 [部署与运维](deployment.md)。

**a) 下载发布包**（推荐）：在 GitHub 的 Releases 页面下载对应平台的压缩包（Linux amd64 / arm64 / armv7、macOS、Windows），解压后得到 `dnsentry` 可执行文件，无需其他依赖。

**b) Docker**：

```sh
docker build -t dnsentry .
DNSENTRY_API_TOKEN=$(openssl rand -hex 24) docker compose -f deploy/compose.yaml up -d
```

**c) 从源码**：

```sh
pnpm install && pnpm start
```

## 2. 第一次启动

```sh
./dnsentry            # 在当前目录使用 data/config.yaml
```

首次运行会自动创建：

- `data/config.yaml`：配置文件（默认值见 [配置参考](configuration.md)）
- `data/rules.txt`：本地过滤规则文件

终端里会看到 DNS 和控制台的监听地址：

```text
level=INFO msg="DNS listening" address=:15353 protocols=udp,tcp
level=INFO msg="web console listening" url=http://127.0.0.1:18080
```

默认 DNS 端口是 **15353**（避开需要特权的 53 端口）。生产环境想用标准端口，见下面第 4 步。

## 3. 打开控制台

浏览器访问 <http://127.0.0.1:18080>。控制台默认**只能在运行它的机器上访问**，且要用 `localhost` 或 IP 地址打开（用其他域名会被拒绝，这是防止网页攻击的安全措施）。要从其他设备访问，需要设置访问令牌，见 [部署与运维](deployment.md#访问控制台)。

## 4. 让设备使用 DNSentry

**先在本机测试**：

```sh
dig @127.0.0.1 -p 15353 example.com
# Windows 的 nslookup 不能指定端口，可以用源码里自带的小工具：
go run ./cmd/dnsentry-query -server 127.0.0.1:15353 example.com
```

**给家里的设备用**：需要 DNSentry 监听 53 端口，并让路由器把它发给所有设备。

1. 给运行 DNSentry 的机器一个固定的内网 IP（在路由器里做 DHCP 静态分配），下文假设为 `192.168.1.2`。
2. 让 DNSentry 监听 53 端口。最简单的办法是首次启动前设置环境变量（或事后在控制台“服务设置 → 监听”里改成 `:53` 并重启）：
   ```sh
   DNSENTRY_DNS_LISTEN=:53 ./dnsentry
   ```
   Linux 上绑定 53 端口需要权限，用 systemd 单元（已配置好）或 `setcap 'cap_net_bind_service=+ep' ./dnsentry`。
3. 在路由器的 DHCP / LAN 设置里，把 **DNS 服务器**设为 `192.168.1.2`，不要再填第二个公共 DNS。
4. 让设备重新连接网络（或等租约到期）。

想让设备无法绕过 DNSentry（写死 DNS 的电视、自带 DoH 的浏览器等），看 [强制所有设备使用 DNSentry](enforce-dns.md)。

## 5. 验证它在工作

1. 在设备上访问几个网站，然后打开控制台的 **查询日志**：应该能看到来自这台设备的请求。
2. 添加一条测试规则：**过滤规则 → 添加本地规则**，输入 `ads.example.com`，再用 `nslookup ads.example.com` 查询，应该得到被拦截的应答。
3. 在 **规则源** 页订阅一个在线列表（比如 AdGuard DNS 过滤器），几十秒后规则数量会出现在仪表盘上。

## 6. 下一步

- 订阅规则源、调整拦截方式：[过滤规则](filtering.md)
- 换上游、加密 DNS、缓存：[解析与加密 DNS](dns.md)
- 每个页面的用法：[控制台使用指南](console.md)
- 出问题了：[故障排查](troubleshooting.md)
