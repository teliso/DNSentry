// Command dnsentry runs the DNS filtering service and its Web console.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // time zone names work even where the system has no zoneinfo (containers)

	"github.com/teliso/DNSentry/internal/app"
	"github.com/teliso/DNSentry/internal/buildinfo"
	"github.com/teliso/DNSentry/web"
)

func main() {
	configPath := flag.String("config", "", "path to the YAML configuration file, created with defaults if missing (default: <data-dir>/config.yaml, else data/config.yaml)")
	dataDir := flag.String("data-dir", os.Getenv("DNSENTRY_DATA_DIR"), "working directory for all data: configuration, rules, logs, certificates (env DNSENTRY_DATA_DIR); created if missing")
	check := flag.Bool("check", false, "validate the configuration and exit")
	version := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.String("healthcheck", "", "GET the given URL (e.g. http://127.0.0.1:18080/readyz), exit 0 on HTTP 200; for container health checks")
	logLevel := flag.String("log-level", envOr("DNSENTRY_LOG_LEVEL", "info"), "log level: debug, info, warn or error")
	logFormat := flag.String("log-format", envOr("DNSENTRY_LOG_FORMAT", "text"), "log format: text or json")
	flag.Parse()

	if *version {
		fmt.Println("dnsentry", buildinfo.String())
		return
	}
	if *healthcheck != "" {
		os.Exit(probe(*healthcheck))
	}
	if err := setupLogging(*logLevel, *logFormat); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := app.SetupPaths(*configPath, *dataDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *check {
		if err := app.CheckConfig(); err != nil {
			fmt.Fprintln(os.Stderr, "configuration error:", err)
			os.Exit(1)
		}
		fmt.Println("configuration OK:", app.ConfigPath())
		return
	}
	if err := app.Run(web.Console()); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// probe requests url and reports whether it answers 200. A loopback http URL is
// also tried as https (the console may be serving TLS with a self-signed
// certificate, which is not verified for the local check).
func probe(url string) int {
	candidates := []string{url}
	if strings.HasPrefix(url, "http://127.0.0.1") || strings.HasPrefix(url, "http://localhost") || strings.HasPrefix(url, "http://[::1]") {
		candidates = append(candidates, "https://"+strings.TrimPrefix(url, "http://"))
	}
	var last error
	for _, candidate := range candidates {
		client := http.Client{Timeout: 3 * time.Second}
		if strings.HasPrefix(candidate, "https://") {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} // loopback health check only
		}
		response, err := client.Get(candidate)
		if err != nil {
			last = err
			continue
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return 0
		}
		last = fmt.Errorf("unhealthy: %s", response.Status)
	}
	fmt.Fprintln(os.Stderr, last)
	return 1
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func setupLogging(level, format string) error {
	var slogLevel slog.Level
	if err := slogLevel.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("invalid -log-level %q", level)
	}
	options := &slog.HandlerOptions{Level: slogLevel}
	var handler slog.Handler
	switch strings.ToLower(format) {
	case "text":
		handler = slog.NewTextHandler(os.Stderr, options)
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, options)
	default:
		return fmt.Errorf("invalid -log-format %q", format)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}
