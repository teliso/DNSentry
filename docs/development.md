# 开发指南

## 环境

- Go 1.26+
- Node 22 与 pnpm（仅改动控制台时需要；只改 Go 代码不需要）

```sh
git clone https://github.com/teliso/DNSentry.git
cd DNSentry
pnpm install
```

## 目录结构

```
cmd/
  dnsentry/          服务入口
  dnsentry-query/    命令行 DNS 查询小工具（测试用）
internal/
  app/               服务核心：配置、DNS 处理、上游、加密 DNS 服务、HTTP API
  rules/             过滤规则：解析、匹配、本地规则文件、远程规则源与磁盘缓存
  cache/             DNS 缓存（分片 LRU、预取、乐观缓存）
  querylog/          查询日志（内存环形缓冲 + 可选落盘）
  dnsname/           域名规范化
  fsutil/            原子写文件等文件工具
  buildinfo/         版本号（构建时通过 ldflags 注入）
web/
  src/               Svelte 5 控制台源码（pages/ 页面，components/ 通用组件，lib/ 状态与工具）
  dist/              构建产物，已提交并通过 embed.FS 打进二进制
deploy/              systemd 单元、Compose 文件、示例配置
docs/                本文档目录
.github/workflows/   CI 与发布流程
```

`internal/app` 里的文件按前缀分组：`api_*` 是 HTTP 接口，`config_*` 是配置的读写、校验与历史，`dns_*` 是 DNS 请求处理，`upstream_*` 是上游池、策略与分流，`secure_*` 是 DoT / DoH / DoQ 服务，`dnscrypt_*` 是 DNSCrypt。

## 常用命令

```sh
pnpm start             # 构建控制台并运行服务
pnpm dev               # 控制台开发服务器（端口 5175，/api 代理到 127.0.0.1:18080）
go run ./cmd/dnsentry  # 只运行后端（使用已有的 web/dist）
make test              # go vet + go test -race + svelte-check
make build             # 静态二进制 ./dnsentry，带版本号
make docker            # 构建本地镜像
```

前端开发流程：先在一个终端运行后端，再在另一个终端 `pnpm dev`，浏览器打开 <http://127.0.0.1:5175> 即可热更新。

## 构建产物必须提交

控制台构建结果 `web/dist` 会被 `//go:embed` 打进二进制，因此**提交在仓库里**，这样只装了 Go 的人也能直接构建。改了 `web/src` 之后：

```sh
pnpm build
git add web/dist
```

CI 会检查 `web/dist` 与源码是否一致，不一致会失败。Go 的嵌入是编译期完成的，前端改完后要重新编译（或重新 `go run`）才能在后端服务里看到。

## 测试与检查

```sh
gofmt -l .                  # 应无输出
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
pnpm check                  # svelte-check（类型检查）
```

测试不依赖外部网络：上游用本地假 DNS 服务模拟，缓存的时钟可以注入（`SetClock`），远程规则源用 `httptest`。新增功能请配套测试，涉及并发的代码务必能通过 `-race`。

## 代码约定

- 后端错误信息面向用户，说明「哪个字段、为什么不对」；配置校验集中在 `config_validation.go`。
- 新增配置项时同时改：`Config`（`config.go`）、YAML 结构（`config_format.go`）、校验、`deploy/config.example.yaml`、[配置参考](configuration.md)；需要重启才生效的项还要加入重启检测。
- 新增 API 时同步 [HTTP API](api.md)。改变行为的 API 要考虑令牌、同源校验与配置路径限制（见 [SECURITY.md](../SECURITY.md)）。
- 前端使用 Svelte 5 runes 和 TypeScript；页面不要直接 `fetch`，通过 `lib/api.ts`；配置编辑走 `store.svelte.ts` 中的草稿与保存栏。CSP 禁止内联脚本。
- 布局上避免相邻卡片互相拉伸高度，不使用 `resize`。
- 不在配置里引入依赖客户端 IP / MAC 的策略，这类标识在现代设备上不稳定，项目有意不做。

## 版本与发布

版本号来自 git 标签，通过 `-ldflags "-X github.com/teliso/DNSentry/internal/buildinfo.Version=…"` 写入；本地构建没有标签时显示为 `dev` 或 `git describe` 的结果。

发布步骤：

1. 确认 `main` 上 CI 通过，`web/dist` 是最新的。
2. 打标签并推送：

   ```sh
   git tag v1.2.3
   git push origin v1.2.3
   ```

3. Release 工作流会自动：跑测试；交叉编译 linux（amd64 / arm64 / armv7）、macOS（amd64 / arm64）和 Windows（amd64）；生成 `SHA256SUMS` 并创建 GitHub Release；向 GHCR 推送多架构镜像（`ghcr.io/<owner>/dnsentry`，带 `1.2.3`、`1.2` 标签，非预发布版本还会更新 `latest`）。

带连字符的标签（如 `v1.2.3-rc1`）会被标记为预发布，不更新 `latest`。

## 许可证

贡献的代码按 AGPL-3.0 授权，见 [LICENSE](../LICENSE)。
