# Common tasks. `pnpm` equivalents: pnpm build / pnpm check / pnpm start.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/teliso/DNSentry/internal/buildinfo.Version=$(VERSION)

.PHONY: all web build test lint run docker clean

all: web build

web:
	pnpm install --frozen-lockfile
	pnpm build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dnsentry ./cmd/dnsentry

test:
	go vet ./...
	go test -race ./...
	pnpm check

run: web
	go run ./cmd/dnsentry

docker:
	docker build --build-arg VERSION=$(VERSION) -t dnsentry:$(VERSION) -t dnsentry:latest .

clean:
	rm -f dnsentry
