# syntax=docker/dockerfile:1

# --- Web console
FROM node:22-alpine AS web
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY web/package.json web/
RUN pnpm install --frozen-lockfile
COPY web web
RUN pnpm build

# --- Server
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY web/embed.go web/
COPY --from=web /src/web/dist web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/teliso/DNSentry/internal/buildinfo.Version=${VERSION}" \
    -o /out/dnsentry ./cmd/dnsentry
# The data directory must belong to the runtime user so a fresh volume is writable.
RUN mkdir -p /out/data

# --- Runtime
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dnsentry /usr/local/bin/dnsentry
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/dnsentry
WORKDIR /var/lib/dnsentry
# Used only when the first-run configuration is created in the volume.
ENV DNSENTRY_DNS_LISTEN=:53 \
    DNSENTRY_WEB_LISTEN=:18080 \
    DNSENTRY_ALLOW_PUBLIC_WEB=1
VOLUME /var/lib/dnsentry
EXPOSE 53/udp 53/tcp 18080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["/usr/local/bin/dnsentry", "-healthcheck", "http://127.0.0.1:18080/readyz"]
ENTRYPOINT ["/usr/local/bin/dnsentry", "-config", "/var/lib/dnsentry/config.yaml"]
