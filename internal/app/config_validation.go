package app

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/rules"
)

func validateConfig(config *Config) (*Config, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	config.HTTPListen = strings.TrimSpace(config.HTTPListen)
	if config.HTTPListen == "" || strings.TrimSpace(config.RulesFile) == "" {
		return nil, errors.New("config is missing required fields")
	}
	dnsListens, err := normalizeListenAddresses("dns listen", "", config.DNSListens)
	if err != nil {
		return nil, err
	}
	if len(dnsListens) == 0 {
		return nil, errors.New("dns listens must contain at least one address")
	}
	config.DNSListens = dnsListens
	if err := validateListenAddress("web listen", config.HTTPListen); err != nil {
		return nil, err
	}
	if config.UpstreamTimeout <= 0 {
		config.UpstreamTimeout = 4
	}
	config.UpstreamMode = strings.ToLower(strings.TrimSpace(config.UpstreamMode))
	if config.UpstreamMode == "" {
		config.UpstreamMode = "load_balance"
	}
	if config.UpstreamMode != "load_balance" && config.UpstreamMode != "parallel" && config.UpstreamMode != "fastest_addr" {
		return nil, errors.New("invalid upstream_mode: use load_balance, parallel, or fastest_addr")
	}
	if config.CacheSize < 0 {
		return nil, errors.New("cache_size must not be negative")
	}
	if config.CacheSize == 0 {
		config.CacheSize = 4 << 20
	}
	config.QueryLogFile = strings.TrimSpace(config.QueryLogFile)
	if config.QueryLogFile == "" {
		config.QueryLogFile = filepath.Join("data", "querylog")
	}
	if config.QueryLogRetentionDays == 0 {
		config.QueryLogRetentionDays = 7
	}
	if config.QueryLogRetentionDays < 1 || config.QueryLogRetentionDays > 365 {
		return nil, errors.New("query_log_retention_days must be between 1 and 365")
	}
	if config.BlockingMode == "" {
		config.BlockingMode = "default"
	}
	if config.BlockingMode != "default" && config.BlockingMode != "nxdomain" && config.BlockingMode != "null_ip" && config.BlockingMode != "custom_ip" && config.BlockingMode != "refused" {
		return nil, errors.New("invalid blocking_mode: use default, nxdomain, null_ip, custom_ip, or refused")
	}
	if config.BlockingIPv4 == "" {
		config.BlockingIPv4 = "0.0.0.0"
	}
	if config.BlockingIPv6 == "" {
		config.BlockingIPv6 = "::"
	}
	if err := validateAddressFamily("blocking_ipv4", config.BlockingIPv4, false); err != nil {
		return nil, err
	}
	if err := validateAddressFamily("blocking_ipv6", config.BlockingIPv6, true); err != nil {
		return nil, err
	}
	if config.OptimisticAnswerTTL == 0 {
		config.OptimisticAnswerTTL = cache.DefaultOptimisticAnswerTTL
	}
	if config.OptimisticMaxAge == 0 {
		config.OptimisticMaxAge = cache.DefaultOptimisticMaxAgeSeconds
	}
	if config.OptimisticAnswerTTL > config.OptimisticMaxAge {
		return nil, errors.New("cache_optimistic_answer_ttl must be less than or equal to cache_optimistic_max_age")
	}
	if config.BlockedResponseTTL == 0 {
		config.BlockedResponseTTL = 10
	}
	if config.CacheTTLMax > 0 && config.CacheTTLMin > config.CacheTTLMax {
		return nil, errors.New("cache_ttl_min must be less than or equal to cache_ttl_max")
	}
	config.DNSSECTrustAnchorFile = strings.TrimSpace(config.DNSSECTrustAnchorFile)
	if config.DNSSECAutoUpdate {
		if len(config.DNSSECTrustAnchors) > 0 {
			return nil, errors.New("dnssec_auto_update cannot be used with dnssec_trust_anchors")
		}
		if config.DNSSECTrustAnchorFile == "" {
			config.DNSSECTrustAnchorFile = defaultDNSSECTrustAnchorFile
		}
	}
	if config.DNSSECTrustAnchorFile != "" && len(config.DNSSECTrustAnchors) > 0 {
		return nil, errors.New("dnssec_trust_anchor_file and dnssec_trust_anchors cannot be used together")
	}
	if config.DNSSECAutoUpdate && !config.DNSSECValidate {
		return nil, errors.New("dnssec_auto_update requires dnssec_validate")
	}
	if err := validateDNSSECTrustAnchors(config.DNSSECTrustAnchors); err != nil {
		return nil, err
	}
	if len(config.Upstreams) == 0 {
		return nil, errors.New("upstreams must contain at least one server")
	}
	if len(config.Upstreams) > maxConfiguredUpstreams {
		return nil, fmt.Errorf("upstreams must contain at most %d servers", maxConfiguredUpstreams)
	}
	for index, address := range config.Upstreams {
		normalized, err := validateUpstream(address, false)
		if err != nil {
			return nil, fmt.Errorf("invalid upstreams[%d]: %w", index, err)
		}
		config.Upstreams[index] = normalized
	}
	if len(config.FallbackUpstreams) > maxConfiguredUpstreams {
		return nil, fmt.Errorf("fallback_upstreams must contain at most %d servers", maxConfiguredUpstreams)
	}
	for index, address := range config.FallbackUpstreams {
		normalized, err := validateUpstream(address, false)
		if err != nil {
			return nil, fmt.Errorf("invalid fallback_upstreams[%d]: %w", index, err)
		}
		config.FallbackUpstreams[index] = normalized
	}
	if err := validateUpstreamRoutes(config.UpstreamRoutes); err != nil {
		return nil, err
	}
	if len(config.BootstrapDNS) == 0 {
		config.BootstrapDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if len(config.BootstrapDNS) > maxConfiguredUpstreams {
		return nil, fmt.Errorf("bootstrap_dns must contain at most %d servers", maxConfiguredUpstreams)
	}
	for index, address := range config.BootstrapDNS {
		normalized, err := validateUpstream(address, true)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap_dns[%d]: %w", index, err)
		}
		config.BootstrapDNS[index] = normalized
	}
	if !config.Encryption.Enabled {
		config.Encryption.DoTListen, config.Encryption.DoHListen, config.Encryption.DoH3Listen, config.Encryption.DoQListen = "", "", "", ""
		config.Encryption.DoTListens = nil
		config.Encryption.DoHListens = nil
		config.Encryption.DoH3Listens = nil
		config.Encryption.DoQListens = nil
	} else if err := normalizeEncryptionListeners(&config.Encryption); err != nil {
		return nil, err
	}
	if !config.Encryption.DNSCrypt.Enabled {
		config.Encryption.DNSCrypt.Listen = ""
		config.Encryption.DNSCrypt.Listens = nil
	} else if err := normalizeDNSCryptListeners(&config.Encryption.DNSCrypt); err != nil {
		return nil, err
	}
	if err := validateLocalRecords(config.LocalRecords); err != nil {
		return nil, err
	}
	if err := validateDNSAccessConfig(config.Access); err != nil {
		return nil, err
	}
	if config.Access.MaxConcurrentQueries == 0 {
		config.Access.MaxConcurrentQueries = 2048
	}
	if err := validateEncryptionConfig(config.Encryption); err != nil {
		return nil, err
	}
	sources, err := rules.NormalizeSources(config.RuleSources)
	if err != nil {
		return nil, err
	}
	config.RuleSources = sources
	return config, nil
}

const maxConfiguredListens = 16

func normalizeListenAddresses(name, legacy string, values []string) ([]string, error) {
	if len(values) == 0 && strings.TrimSpace(legacy) != "" {
		values = []string{legacy}
	}
	addresses := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		if err := validateListenAddress(name, value); err != nil {
			return nil, err
		}
		seen[value] = struct{}{}
		addresses = append(addresses, value)
	}
	if len(addresses) > maxConfiguredListens {
		return nil, fmt.Errorf("%s addresses must contain at most %d listeners", name, maxConfiguredListens)
	}
	return addresses, nil
}

func validateListenAddress(name, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s address %q: expected host:port", name, value)
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("invalid %s address %q: %w", name, value, err)
	}
	if host == "" {
		return nil
	}
	if !validHost(host) {
		return fmt.Errorf("invalid %s address %q: invalid host", name, value)
	}
	return nil
}

func validateAddressFamily(name, value string, wantIPv6 bool) error {
	ip := net.ParseIP(value)
	valid := ip != nil && ((wantIPv6 && ip.To4() == nil && ip.To16() != nil) || (!wantIPv6 && ip.To4() != nil && !strings.Contains(value, ":")))
	if !valid {
		family := "IPv4"
		if wantIPv6 {
			family = "IPv6"
		}
		return fmt.Errorf("%s must be a valid %s address", name, family)
	}
	return nil
}

func validateUpstream(value string, plainOnly bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("address is empty")
	}
	if !strings.Contains(value, "://") {
		if host, port, err := net.SplitHostPort(value); err == nil {
			if !validHost(host) {
				return "", errors.New("invalid host")
			}
			if err := validatePort(port); err != nil {
				return "", err
			}
			return value, nil
		}
		if net.ParseIP(value) != nil {
			return normalizeUpstream(value), nil
		}
		return "", errors.New("expected an IP address or host:port")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", errors.New("invalid upstream URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "sdns" || scheme == "sdns+tcp" || scheme == "sdns+udp" {
		if plainOnly {
			return "", errors.New("DNSCrypt stamp is not allowed here")
		}
		if err := validateDNSCryptUpstreamStamp(value); err != nil {
			return "", err
		}
		return value, nil
	}
	if scheme != "https" && scheme != "h3" && scheme != "tls" && scheme != "dot" && scheme != "quic" && scheme != "doq" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.Host == "" || !validHost(parsed.Hostname()) {
		return "", errors.New("invalid host")
	}
	if port := parsed.Port(); port != "" {
		if err := validatePort(port); err != nil {
			return "", err
		}
	}
	return value, nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validHost(value string) bool {
	if value == "" {
		return false
	}
	if ip := net.ParseIP(strings.Split(value, "%")[0]); ip != nil {
		return true
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
