package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConsoleRejectsRebindingHostsWithoutToken(t *testing.T) {
	api := &API{resolver: &DNSServer{config: &Config{}}}
	for host, want := range map[string]int{
		"127.0.0.1:18080":  http.StatusNotFound, // reaches the router: any status but 403
		"localhost:18080":  http.StatusNotFound,
		"[::1]:18080":      http.StatusNotFound,
		"app.localhost":    http.StatusNotFound,
		"192.168.1.5:8080": http.StatusNotFound,
		"evil.example.com": http.StatusForbidden, // DNS rebinding: public name resolving to loopback
		"evil.example:80":  http.StatusForbidden,
	} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/unknown", nil)
		request.Host = host
		request.RemoteAddr = "127.0.0.1:4000"
		recorder := httptest.NewRecorder()
		api.handle(recorder, request)
		if recorder.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, recorder.Code, want)
		}
	}
}

func TestHostCheckDoesNotApplyWithToken(t *testing.T) {
	api := &API{apiToken: "secret", resolver: &DNSServer{config: &Config{}}}
	request := httptest.NewRequest(http.MethodGet, "http://dns.example.com/api/unknown", nil)
	request.RemoteAddr = "192.0.2.7:4000"
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("authenticated request by name = %d, want 404 (reached router)", recorder.Code)
	}
}

func TestFailedAuthenticationIsThrottled(t *testing.T) {
	api := &API{apiToken: "secret", resolver: &DNSServer{config: &Config{}}}
	attempt := func(token, remote string) int {
		request := httptest.NewRequest(http.MethodGet, "http://dns.example/api/status", nil)
		request.RemoteAddr = remote
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		api.handle(recorder, request)
		return recorder.Code
	}
	for index := 0; index < authFailureLimit; index++ {
		if code := attempt("wrong", "192.0.2.9:1000"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", index, code)
		}
	}
	if code := attempt("secret", "192.0.2.9:1001"); code != http.StatusTooManyRequests {
		t.Fatalf("blocked client with the right token = %d, want 429", code)
	}
	if code := attempt("wrong", "192.0.2.10:1000"); code != http.StatusUnauthorized {
		t.Fatalf("other clients are unaffected, got %d", code)
	}
}

func TestAuthThrottleExpiresAndSuccessResets(t *testing.T) {
	var throttle authThrottle
	for index := 0; index < authFailureLimit; index++ {
		throttle.fail("c")
	}
	if throttle.blocked("c") <= 0 {
		t.Fatal("expected a block")
	}
	throttle.failures["c"].start = time.Now().Add(-2 * authFailureWindow)
	if throttle.blocked("c") != 0 {
		t.Fatal("block should expire with the window")
	}
	throttle.fail("d")
	throttle.succeed("d")
	if _, ok := throttle.failures["d"]; ok {
		t.Fatal("success should clear failures")
	}
}

func TestAPIConfigPathsAreConfined(t *testing.T) {
	saved := Config{RulesFile: "data/rules.txt", QueryLogFile: "/var/log/dnsentry/query", Encryption: EncryptionConfig{Certificate: "/etc/ssl/dns.crt"}}
	for name, mutate := range map[string]func(*Config){
		"absolute rules file":   func(c *Config) { c.RulesFile = "/etc/cron.d/x" },
		"parent traversal":      func(c *Config) { c.QueryLogFile = "../../etc/passwd" },
		"absolute private key":  func(c *Config) { c.Encryption.PrivateKey = "/root/.ssh/id_rsa" },
		"trust anchor traverse": func(c *Config) { c.DNSSECTrustAnchorFile = "data/../../x" },
	} {
		next := saved
		mutate(&next)
		if err := checkAPIPaths(next, saved); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	next := saved
	next.RulesFile = "data/other-rules.txt" // relative and inside the working directory
	if err := checkAPIPaths(next, saved); err != nil {
		t.Errorf("relative path rejected: %v", err)
	}
	if err := checkAPIPaths(saved, saved); err != nil {
		t.Errorf("unchanged absolute paths must be accepted: %v", err)
	}
}

func TestPutConfigRejectsEscapingPath(t *testing.T) {
	api := newConfigTestAPI(t)
	next := api.configResponse()
	next.QueryLogFile = "/tmp/outside"
	if response := callAPI(t, api, http.MethodPut, "/api/config", next); response.Code != http.StatusBadRequest {
		t.Fatalf("PUT /config = %d %s", response.Code, response.Body)
	}
}
