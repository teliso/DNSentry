# DNSentry

A self-hosted DNS filtering and resolving service with a web console. It blocks ads, trackers and malicious domains locally, forwards everything else to the upstreams you choose (encrypted DNS supported), and can serve DoT / DoH / DoH3 / DoQ / DNSCrypt itself.

中文说明见 [README.md](README.md). The console has an **EN / 中文** switch in the top bar (it follows the browser language at first). The documents under `docs/` are in Chinese.

## Features

- **Filtering**: local rules (AdGuard / hosts / plain domain syntax) plus subscribed online rule sources; downloaded lists are cached on disk. **Rule check** explains why any domain is blocked or allowed.
- **Resolving**: multiple upstreams (plain DNS, DoT, DoH, DoH3, DoQ, DNSCrypt), load balancing / parallel requests, fallback upstreams, automatic circuit breaking, **per-domain routing**, local records, DNSSEC validation.
- **Cache**: sharded LRU with negative caching, TTL limits, optimistic cache and prefetching.
- **Observability**: dashboard (30 minutes to 90 days of traffic, upstream latency, slowest and failing domains), query log (optionally persisted, or switched off entirely), program log, Prometheus metrics, health alerts, **configuration history**.
- **Parental control**: block whole services with one click, force safe search, schedules by weekday and time, temporary pause.
- **Security**: the console listens on loopback by default; public access requires a password or token; client allow/deny lists, rate limiting, concurrency limit, DNS rebinding protection.
- **Easy to deploy**: one static binary with the console embedded; default configuration generated on first start; systemd unit, Docker image and Compose file included.

## Quick start

Go 1.27+ is required; running the console from source also needs Node 22 and pnpm.

```sh
git clone https://github.com/teliso/DNSentry.git
cd DNSentry
pnpm install
pnpm start
```

The first start creates a default configuration under `data/`. Open <http://127.0.0.1:18080> for the console. DNS listens on `:15353` by default:

```sh
go run ./cmd/dnsentry-query -server 127.0.0.1:15353 example.com
```

Console password: set it under Settings → Console login (8+ characters), or write `web.auth.username` / `web.auth.password` in `config.yaml` (any length; it is converted to a hash on the next start and removed from the file).
