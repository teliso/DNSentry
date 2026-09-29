# 让局域网内所有设备使用 DNSentry

目标：设备**不需要任何设置**，上网时的 DNS 查询都经过 DNSentry。这一步在路由器上完成，DNSentry 本身无法强制客户端使用它。分三层，从必需到可选：

1. 通过 DHCP 把 DNSentry 发给所有设备（必需）
2. 拦截或重定向绕过它的传统 DNS（推荐）
3. 应对自带加密 DNS 的应用（尽力而为，无法做到 100%）

## 0. 先准备好 DNSentry

- 给运行 DNSentry 的机器一个**固定的内网 IP**（在路由器里做 DHCP 静态分配），下文记作 `192.168.1.2`。
- 让它监听 53 端口：`DNSENTRY_DNS_LISTEN=:53`（systemd 单元已经这样设置，Docker 镜像默认如此）。如果保持 `:15353`，需要在路由器上做端口转换，见第 2 节。
- 确认服务能自启并在异常时重启（systemd 的 `Restart=on-failure`、Docker 的 `restart: unless-stopped`）。**启用强制重定向后 DNSentry 一旦停止，全家断网**，请把这一点当作真正的依赖来对待。

## 1. 通过 DHCP 下发（必需）

在路由器的 LAN / DHCP 设置里，把 **DNS 服务器**设为 `192.168.1.2`。

- **不要再填第二个公共 DNS**（如 8.8.8.8）。很多系统会把两个 DNS 当作平级，一部分查询会绕过 DNSentry。
- 想要冗余的话，第二个 DNS 填另一台也运行 DNSentry 的机器。
- 路由器自己的 WAN 侧 DNS 保持默认即可，它只用于路由器自身的解析。
- **IPv6**：如果局域网启用了 IPv6，路由器会通过 RA（路由通告）或 DHCPv6 下发 IPv6 DNS，设备可能优先用它。要么把 IPv6 DNS 也设为 DNSentry 的 IPv6 地址，要么关闭 RA 里的 DNS 下发（RDNSS / DHCPv6 DNS），让设备只用上面的 IPv4 DNS。

改完后让设备重新连接（或等待租约到期），在设备上执行 `nslookup example.com` 看服务器地址；DNSentry 的“查询日志”里能看到这台设备的请求即为生效。

## 2. 拦截或重定向绕过它的传统 DNS（推荐）

有些设备把 DNS 服务器写死成 `8.8.8.8` 等地址。在路由器的防火墙里处理发往公网 53 端口的流量，有两种做法：

| 做法 | 效果 | 代价 |
| --- | --- | --- |
| **丢弃**：禁止 LAN 设备访问除 DNSentry 以外的 53 端口 | 写死 DNS 的设备解析失败 | 这些设备会没网，要靠你发现并处理 |
| **重定向（DNAT）**：把这些请求转给 DNSentry | 写死 DNS 的设备也被过滤，对它们透明 | 见下面的“客户端地址会丢失” |

> **客户端地址会丢失**：如果 DNSentry 与被重定向的设备在**同一个网段**，路由器必须对重定向后的流量做源地址转换（否则回包会绕过路由器，被设备丢弃）。这样 DNSentry 看到的所有请求都来自路由器的地址，查询日志里就分不出是哪台设备。想保留客户端地址，就把 DNSentry **直接装在路由器上**（OpenWrt 等），或者放在与客户端不同的网段。

### OpenWrt：重定向（DNSentry 在路由器上或另一网段）

```sh
uci add firewall redirect
uci set firewall.@redirect[-1].name='Force DNSentry'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].src_ip='!192.168.1.2'      # DNSentry 自己的上游查询不要被重定向，否则会死循环
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_ip='192.168.1.2'
uci set firewall.@redirect[-1].dest_port='53'             # DNSentry 监听 15353 时改成 15353
uci set firewall.@redirect[-1].proto='tcp udp'
uci set firewall.@redirect[-1].target='DNAT'
uci commit firewall && /etc/init.d/firewall restart
```

DNSentry 就装在这台 OpenWrt 上时，把 `dest_ip` 设为路由器自己的 LAN 地址即可。

### 通用 Linux 路由器（nftables）

假设 LAN 接口为 `br-lan`，DNSentry 在 `192.168.1.2`：

```nft
table inet dnsentry {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "br-lan" ip saddr != 192.168.1.2 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.168.1.2:53
  }
  # DNSentry 与客户端同网段时需要下面这条，代价见上面的提示
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "br-lan" ip daddr 192.168.1.2 meta l4proto { tcp, udp } th dport 53 masquerade
  }
}
```

### 只想丢弃、不重定向

```nft
table inet dnsentry_drop {
  chain forward {
    type filter hook forward priority filter - 1; policy accept;
    iifname "br-lan" ip daddr != 192.168.1.2 meta l4proto { tcp, udp } th dport 53 reject
  }
}
```

## 3. 应对自带加密 DNS 的应用（尽力而为）

浏览器、部分手机和电视自带 DoH/DoT，直接连公共解析器，看上去只是普通的 HTTPS 流量，路由器不容易区分。可以叠加这些措施，它们能覆盖大多数情况，但没有一种是绝对的：

1. **禁用 DoT 和 DoQ**：DoT 用 TCP 853，DoQ 用 UDP 853，它们端口固定，直接在路由器上禁止 LAN 访问公网的 853 端口即可（DNSentry 自己提供的 853 监听不受影响）：
   ```nft
   iifname "br-lan" ip daddr != 192.168.1.2 meta l4proto { tcp, udp } th dport 853 reject
   ```
2. **让浏览器关掉自动 DoH（“金丝雀域名”）**：
   - Firefox 会先查询 `use-application-dns.net`，如果解析失败（NXDOMAIN），就不会启用它的 DoH。
   - Apple 设备会查询 `mask.icloud.com` 和 `mask-h2.icloud.com` 判断能否使用“iCloud 专用代理”，返回 NXDOMAIN 会让它在此网络上自动关闭。
   - 在“过滤规则”里添加（并把“DNS 设置 → 拦截响应”的拦截模式设为 **NXDOMAIN**，其他模式返回的是假地址，不一定触发关闭）：
     ```text
     ||use-application-dns.net^
     ||mask.icloud.com^
     ||mask-h2.icloud.com^
     ```
   - Chrome 只在系统 DNS 本身支持 DoH 时才自动升级，指向 DNSentry 的普通 DNS 不会被升级，通常无需处理。
3. **屏蔽公共 DoH 服务器**：DoH 走 443 端口，无法按端口禁用，只能按目的地址禁用。可以从社区维护的 DoH 服务器列表（搜索 “public DoH server list”）导入域名，加到 DNSentry 的规则里让这些域名解析不出来；应用如果用的是写死的 IP 地址，还需要在路由器上按 IP 封禁。
4. **写死 IP 的 DoH 客户端、VPN、代理**：这些没有办法在 DNS 层拦住，只能在路由器上封 IP 或者接受这一点。

## 验证

- 在设备上手动指定公共 DNS，再查询：`nslookup example.com 8.8.8.8`。使用重定向的话，答案来自 DNSentry（查询日志里可见）；使用丢弃的话应该超时。
- 在设备上访问一个被你拦截的域名，确认被拦截。
- 用 DoT 客户端（如 `kdig +tls @1.1.1.1 example.com`）测试，应该失败。
- 一段时间后看 DNSentry 的仪表盘：如果家里的设备数量明显多于日志里出现的来源地址，说明还有设备在绕过它。

## 什么时候不要做第 2、3 步

- 你有需要用外部 DNS 的设备（公司 VPN 的分流 DNS、某些流媒体盒子）：强制重定向会让它们出问题，可以只做第 1 步。
- 你无法保证 DNSentry 的可用性：强制之后它就是家里的单点。先做好自启和冗余。
