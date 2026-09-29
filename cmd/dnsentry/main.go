// Command dnsentry runs the DNS filtering service and its Web console.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/teliso/DNSentry/internal/app"
	"github.com/teliso/DNSentry/internal/buildinfo"
	"github.com/teliso/DNSentry/web"
)

func main() {
	configPath := flag.String("config", "data/config.yaml", "path to the YAML configuration file (created with defaults if missing)")
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
	app.SetConfigPath(*configPath)
	if *check {
		if err := app.CheckConfig(); err != nil {
			fmt.Fprintln(os.Stderr, "configuration error:", err)
			os.Exit(1)
		}
		fmt.Println("configuration OK:", *configPath)
		return
	}
	if err := app.Run(web.Console()); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func probe(url string) int {
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", response.Status)
		return 1
	}
	return 0
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
