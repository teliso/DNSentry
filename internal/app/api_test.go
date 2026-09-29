package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
)

func TestQueryLogSettingsChangedRequiresRestart(t *testing.T) {
	current := Config{QueryLogSize: 200, QueryLogEnabled: false, QueryLogFile: "data/querylog", QueryLogRetentionDays: 7}
	for _, update := range []func(*Config){
		func(config *Config) { config.QueryLogSize++ },
		func(config *Config) { config.QueryLogEnabled = true },
		func(config *Config) { config.QueryLogFile = "data/audit" },
		func(config *Config) { config.QueryLogRetentionDays++ },
	} {
		next := current
		update(&next)
		if !queryLogSettingsChanged(next, current) {
			t.Fatalf("query log setting change was not marked for restart: %#v", next)
		}
	}
}

func TestAPIRemoteAccessRequiresToken(t *testing.T) {
	api := &API{apiToken: "production-secret"}
	request := httptest.NewRequest(http.MethodGet, "http://dns.example/api/status", nil)
	request.RemoteAddr = "192.0.2.10:4000"
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "token") {
		t.Fatalf("expected unauthorized remote API request, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request.Header.Set("Authorization", "Bearer production-secret")
	request.URL.Path = "/api/unknown"
	recorder = httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected authenticated unknown endpoint to reach router, got %d", recorder.Code)
	}
}

func TestLoopbackAPIExposesMetricsAndClearsCache(t *testing.T) {
	cache := cache.New(1024, true)
	api := &API{cache: cache, logs: querylog.New(10), resolver: &DNSServer{cache: cache, config: &Config{}}}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/metrics", nil)
	request.RemoteAddr = "127.0.0.1:4000"
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "dnsentry_cache_hit_rate") {
		t.Fatalf("expected Prometheus metrics, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/cache/clear", nil)
	request.RemoteAddr = "127.0.0.1:4000"
	request.Header.Set("Origin", "http://127.0.0.1")
	recorder = httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "cleared") {
		t.Fatalf("expected cache clear response, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPublicConfigRedactsPastedPrivateKey(t *testing.T) {
	config := Config{Encryption: EncryptionConfig{CertificatePEM: "certificate", PrivateKeyPEM: "private-key", DNSCrypt: DNSCryptConfig{PrivateKey: "dnscrypt-private", ResolverSecret: "resolver-secret"}}}
	public := publicConfig(config)
	if public.Encryption.CertificatePEM != "certificate" {
		t.Fatal("public config should retain the certificate PEM")
	}
	if public.Encryption.PrivateKeyPEM != "" || public.Encryption.DNSCrypt.PrivateKey != "" || public.Encryption.DNSCrypt.ResolverSecret != "" {
		t.Fatal("public config leaked a private key or resolver secret")
	}
}

func TestLoopbackStateChangingAPIRequiresSameOrigin(t *testing.T) {
	api := &API{resolver: &DNSServer{config: &Config{}}}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/cache/clear", nil)
	request.RemoteAddr = "127.0.0.1:4000"
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin state-changing request status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
