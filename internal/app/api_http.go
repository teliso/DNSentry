package app

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

const (
	maxJSONBodyBytes      = 2 << 20
	httpMaxHeaderBytes    = 1 << 20
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 60 * time.Second
)

func isLoopbackRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(request.RemoteAddr), "[]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func bearerToken(request *http.Request) (string, bool) {
	parts := strings.Fields(request.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

func tokensEqual(provided, expected string) bool {
	providedHash := sha256.Sum256([]byte(provided))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}

func isLoopbackHTTPListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameOriginRequest(request *http.Request, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	} else if request.URL.Scheme != "" {
		scheme = request.URL.Scheme
	}
	return strings.EqualFold(parsed.Scheme, scheme) && strings.EqualFold(parsed.Host, request.Host)
}

func mutatingAPIRequest(request *http.Request) bool {
	if request == nil || !strings.HasPrefix(request.URL.Path, "/api/") {
		return false
	}
	switch request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func sameOriginMutation(request *http.Request) bool {
	if origin := strings.TrimSpace(request.Header.Get("Origin")); origin != "" {
		return sameOriginRequest(request, origin)
	}
	referer := strings.TrimSpace(request.Header.Get("Referer"))
	if referer == "" {
		return false
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return sameOriginRequest(request, parsed.Scheme+"://"+parsed.Host)
}

// decodeJSON reads a size-limited JSON request body into value. On failure it
// writes the error response (413 for oversized bodies, 400 otherwise) and
// returns false.
func decodeJSON(writer http.ResponseWriter, request *http.Request, value any, invalid string) bool {
	err := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maxJSONBodyBytes)).Decode(value)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(writer, http.StatusRequestEntityTooLarge, "request body too large")
	} else {
		writeError(writer, http.StatusBadRequest, invalid)
	}
	return false
}

// withSecurityHeaders hardens every response. The console is served from the
// same origin as the API, so no CORS headers are needed.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers := writer.Header()
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		headers.Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(writer, request)
	})
}

// requestClientIP is the address of the peer that opened the connection.
func requestClientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		return strings.Trim(strings.TrimSpace(request.RemoteAddr), "[]")
	}
	return host
}

// loopbackHost reports whether a Host header names the local machine
// directly: "localhost" (and its subdomains) or an IP literal. Any other name
// could be attacker-controlled DNS pointing at this machine.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	return net.ParseIP(host) != nil
}

const (
	authFailureLimit  = 10
	authFailureWindow = time.Minute
	authTrackedLimit  = 4096
)

// authThrottle slows down token guessing: after authFailureLimit failed
// attempts within authFailureWindow a client is refused until the window ends.
type authThrottle struct {
	mu       sync.Mutex
	failures map[string]*authWindow
}

type authWindow struct {
	count int
	start time.Time
}

func (t *authThrottle) blocked(client string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	window := t.failures[client]
	if window == nil {
		return 0
	}
	remaining := authFailureWindow - time.Since(window.start)
	if remaining <= 0 {
		delete(t.failures, client)
		return 0
	}
	if window.count >= authFailureLimit {
		return remaining
	}
	return 0
}

func (t *authThrottle) fail(client string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failures == nil {
		t.failures = make(map[string]*authWindow)
	}
	window := t.failures[client]
	if window == nil || time.Since(window.start) >= authFailureWindow {
		if len(t.failures) >= authTrackedLimit {
			t.failures = make(map[string]*authWindow) // bounded memory under a flood
		}
		window = &authWindow{start: time.Now()}
		t.failures[client] = window
	}
	window.count++
}

func (t *authThrottle) succeed(client string) {
	t.mu.Lock()
	delete(t.failures, client)
	t.mu.Unlock()
}
