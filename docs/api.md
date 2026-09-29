# HTTP API

控制台使用的就是这套 API，你也可以用脚本调用。所有接口位于 `/api` 下，请求和响应都是 JSON（`/metrics` 除外，是 Prometheus 文本）。

## 认证

- **未设置 `DNSENTRY_API_TOKEN`**：只接受来自本机（回环地址）的请求，并且请求必须用 `localhost` 或 IP 地址作为主机名；写操作（POST / PUT / DELETE）还必须带同源的 `Origin` 或 `Referer` 头。
- **设置了令牌**：所有请求都要带 `Authorization: Bearer <token>`，来源不限。连续 10 次错误会被限制 1 分钟（返回 429 和 `Retry-After`）。

```sh
export TOKEN=...
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.2:18080/api/status
```

错误响应统一为 `{"error": "说明"}`。请求体最大 2 MB。

## 接口一览

| 方法与路径 | 说明 |
| --- | --- |
| `GET /status` | 运行状态、统计、上游健康、规则源状态、版本 |
| `GET /metrics` | Prometheus 指标 |
| `GET /config` | 当前保存的配置 |
| `PUT /config` | 保存配置，立即应用可热更新的部分 |
| `GET /config/history` | 配置版本列表（新的在前） |
| `POST /config/restore` | 恢复配置，可选 `{"id": "…"}`，默认恢复上一个版本 |
| `POST /cache/clear` | 清空 DNS 缓存 |
| `POST /upstreams/test` | 测试上游 `{"upstreams": [...], "domain": "example.com"}` |
| `GET /logs` | 查询日志（分页） |
| `GET /rules` | 规则（分页） |
| `POST /rules` | 添加本地规则 `{"domain": "…", "action": "block"|"allow"}` |
| `DELETE /rules?domain=&action=` | 删除本地规则 |
| `GET /rules/check?domain=` | 解释一个域名命中的规则 |
| `GET /rules/local`、`PUT /rules/local` | 读取 / 整体替换 `rules.txt` 文本 |
| `POST /reload` | 从磁盘重新载入 `rules.txt` |
| `GET /sources`、`PUT /sources` | 规则源列表 / 整体替换 |
| `POST /sources/refresh` | 立即更新规则源 `{"url": "…"}`，空则更新全部 |

## 常用接口详解

### `GET /status`

返回一个大的对象，主要字段：`version`、`restart_required`、`config_path`、`rules_file`、`total_queries`、`blocked_queries`、`rules`、`local_rules`、`cache`（命中率、条目、字节数、预取次数等）、`dnssec`、`security`（被拒绝 / 限速 / 过载 / Rebinding 的计数）、`dnscrypt`（运行状态与 stamp）、`series`（最近 30 分钟每分钟的查询和拦截数）、`dashboard`（排行）、`upstream_health`（每个上游的健康状态和 30 分钟 `history`）、`upstream_routes`（分流及其上游健康）、`fallback_upstream_health`、`rule_sources`（规则源及运行状态）。

### `GET /config` / `PUT /config`

配置对象的 JSON 形式，字段与 [配置文件](configuration.md) 一一对应（例如 `dns_listens`、`upstreams`、`upstream_routes`、`cache_size`、`encryption.dot_listens`）。

- 私钥类字段（`private_key_pem`、DNSCrypt 的 `private_key` 和 `resolver_secret`）**不会返回**；`PUT` 时留空表示保持现有值。
- `rule_sources` 不由 `PUT /config` 修改（用 `PUT /sources`），请求里的值会被忽略。
- 成功返回 200 和保存后的配置。监听地址、控制台地址、规则文件、日志存储、加密 DNS 这类启动时设置会被保存，但要重启才生效——重启后才生效的情况可以从 `GET /status` 的 `restart_required` 得知。
- 规则文件、日志、信任锚文件、证书、私钥这些路径，改动时只能是工作目录内的相对路径（否则 400）。

### `GET /logs`

参数：`search`（域名或客户端地址中包含的文字）、`action`、`offset`、`limit`（默认 100，最大 500）。

```json
{
  "total": 152,
  "actions": ["block", "cached", "forwarded"],
  "items": [
    { "time": "2026-09-29T10:54:01Z", "client": "192.168.1.30", "domain": "ads.example.com",
      "type": "A", "action": "block", "duration_ms": 0,
      "rule": "||ads.example.com^", "rule_source": "" }
  ]
}
```

`action` 取值：`block`、`allow`、`forwarded`、`cached`、`optimistic`、`local`、`aaaa_blocked`、`denied`、`rate_limited`、`overloaded`、`rebinding_blocked`、`error`。

### `GET /rules`

参数：`search`、`action`（`block` / `allow`）、`source`（`local` 或规则源地址）、`offset`、`limit`（默认 100，最大 500）。

```json
{ "total": 3008, "items": [ { "domain": "doubleclick.net", "action": "block" },
                            { "domain": "ad0.tracker.test", "action": "block", "source": "https://…/ads.txt" } ] }
```

`source` 为空表示本地规则。

### `GET /rules/check?domain=`

```json
{ "domain": "x.ads.example.com",
  "rule": { "domain": "ads.example.com", "action": "block" },
  "candidates": [ { "domain": "ads.example.com", "action": "block" } ] }
```

`rule` 是生效的规则（没有匹配则省略），`candidates` 是所有匹配该域名或其上级域名的规则。

### `PUT /rules/local`

请求体 `{"text": "…整个 rules.txt…"}`，返回 `{"rules": 12, "ignored": 1, "ignored_lines": [7]}`。

### 规则源

`PUT /sources` 的请求体是数组，每项 `{"url", "name", "enabled", "interval_minutes"}`；返回带运行状态的完整列表：

```json
[{ "url": "https://…/ads.txt", "name": "AdGuard DNS 过滤器", "enabled": true, "interval_minutes": 1440,
   "last_updated": "…", "last_checked": "…", "last_error": "", "rule_count": 52000, "updating": false }]
```

`POST /sources/refresh` 立即返回 202，下载在后台进行，可以轮询 `GET /sources` 看 `updating`。

### 配置历史

`GET /config/history` 返回 `[{ "id", "time", "current", "changes": ["dns.upstreams"], "more_changes" }]`（`changes` 只有设置项的名字，不含值）。`POST /config/restore` 用 `id` 指定版本，不带则恢复到上一个版本；恢复后会作为一个新版本记录。

## 健康检查（无需令牌）

- `GET /healthz`：进程存活，返回 `ok`。
- `GET /readyz`：至少一个 DNS 监听已就绪时返回 `ready`，否则 503。
