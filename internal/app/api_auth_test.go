package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/teliso/DNSentry/internal/auth"
)

func TestMain(m *testing.M) {
	auth.Cost = bcrypt.MinCost
	os.Exit(m.Run())
}

// authCall sends a request as a browser on the same machine would.
func authCall(t *testing.T, api *API, method, path string, body any, cookie *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(body)
	request := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(data))
	request.RemoteAddr = "127.0.0.1:4000"
	request.Header.Set("Origin", "http://127.0.0.1")
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	api.handle(recorder, request)
	return recorder
}

func sessionOf(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Value != "" {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie must be HttpOnly and SameSite=Strict: %#v", cookie)
			}
			return cookie
		}
	}
	t.Fatalf("no session cookie in %d %s", response.Code, response.Body)
	return nil
}

func TestConsoleLoginLifecycle(t *testing.T) {
	api := newConfigTestAPI(t)
	if status := authCall(t, api, http.MethodGet, "/api/status", nil, nil); status.Code != http.StatusOK {
		t.Fatalf("loopback without a password = %d", status.Code)
	}

	// Setting a password signs the caller in and locks everybody else out.
	set := authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "correct horse"}, nil)
	if set.Code != http.StatusOK {
		t.Fatalf("set password = %d %s", set.Code, set.Body)
	}
	first := sessionOf(t, set)
	if _, err := os.Stat(authFilePath()); err != nil {
		t.Fatalf("credentials were not saved: %v", err)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("a password must be required even on loopback, got %d", code)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, first).Code; code != http.StatusOK {
		t.Fatalf("session = %d", code)
	}
	var status authStatus
	if err := json.Unmarshal(authCall(t, api, http.MethodGet, "/api/auth", nil, first).Body.Bytes(), &status); err != nil || !status.Configured || !status.Authenticated || status.Username != "admin" {
		t.Fatalf("auth status = %#v %v", status, err)
	}
	var anonymous authStatus
	if err := json.Unmarshal(authCall(t, api, http.MethodGet, "/api/auth", nil, nil).Body.Bytes(), &anonymous); err != nil || !anonymous.Configured || anonymous.Authenticated || anonymous.Username != "" {
		t.Fatalf("anonymous auth status = %#v %v", anonymous, err)
	}

	// Signing in: wrong password, cross-origin, then the real thing.
	if code := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "nope"}, nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", code)
	}
	if code := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "correct horse"}, nil, "Origin", "http://evil.example").Code; code != http.StatusForbidden {
		t.Fatalf("cross-origin sign-in = %d", code)
	}
	login := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "correct horse"}, nil)
	second := sessionOf(t, login)
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, second).Code; code != http.StatusOK {
		t.Fatalf("after sign-in = %d", code)
	}
	// Changing state with a session still needs a same-origin request.
	if code := authCall(t, api, http.MethodPost, "/api/cache/clear", nil, second, "Origin", "http://evil.example").Code; code != http.StatusForbidden {
		t.Fatalf("cross-origin mutation with a session = %d", code)
	}

	// Sign out ends only that session.
	if code := authCall(t, api, http.MethodPost, "/api/logout", nil, second).Code; code != http.StatusOK {
		t.Fatalf("logout = %d", code)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, second).Code; code != http.StatusUnauthorized {
		t.Fatalf("a signed-out session still works: %d", code)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, first).Code; code != http.StatusOK {
		t.Fatalf("signing out one browser ended another: %d", code)
	}

	// Changing the password needs the current one and signs everybody else out.
	if code := authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "another password"}, first).Code; code != http.StatusForbidden {
		t.Fatalf("change without the current password = %d", code)
	}
	changed := authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "another password", "current_password": "correct horse"}, first)
	if changed.Code != http.StatusOK {
		t.Fatalf("change = %d %s", changed.Code, changed.Body)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, first).Code; code != http.StatusUnauthorized {
		t.Fatalf("an old session survived a password change: %d", code)
	}
	third := sessionOf(t, changed)
	if code := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "correct horse"}, nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("the old password still works: %d", code)
	}

	// Removing the login needs the password too, and turns the console back to loopback-only.
	if code := authCall(t, api, http.MethodDelete, "/api/auth", map[string]string{"current_password": "wrong"}, third).Code; code != http.StatusForbidden {
		t.Fatalf("remove with a wrong password = %d", code)
	}
	if code := authCall(t, api, http.MethodDelete, "/api/auth", map[string]string{"current_password": "another password"}, third).Code; code != http.StatusOK {
		t.Fatalf("remove = %d", code)
	}
	if auth.Exists(authFilePath()) {
		t.Fatal("the credentials file was not removed")
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, nil).Code; code != http.StatusOK {
		t.Fatalf("after removing the login = %d", code)
	}
}

func TestLoginValidationAndThrottle(t *testing.T) {
	api := newConfigTestAPI(t)
	if code := authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "short"}, nil).Code; code != http.StatusBadRequest {
		t.Fatalf("short password = %d", code)
	}
	if code := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "a", "password": "b"}, nil).Code; code != http.StatusBadRequest {
		t.Fatalf("sign-in without a password set = %d", code)
	}
	authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "correct horse"}, nil)
	var last int
	for i := 0; i < authFailureLimit+2; i++ {
		last = authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "guess"}, nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("repeated wrong passwords were not throttled: %d", last)
	}
	if code := authCall(t, api, http.MethodPost, "/api/login", map[string]string{"username": "admin", "password": "correct horse"}, nil).Code; code != http.StatusTooManyRequests {
		t.Fatalf("a blocked client must stay blocked even with the right password: %d", code)
	}
}

func TestAPITokenStillWorksNextToALogin(t *testing.T) {
	api := newConfigTestAPI(t)
	api.apiToken = "script-token"
	authCall(t, api, http.MethodPut, "/api/auth", map[string]string{"username": "admin", "password": "correct horse"}, nil, "Authorization", "Bearer script-token")
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, nil, "Authorization", "Bearer script-token").Code; code != http.StatusOK {
		t.Fatalf("token = %d", code)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, nil, "Authorization", "Bearer wrong").Code; code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d", code)
	}
	if code := authCall(t, api, http.MethodGet, "/api/status", nil, nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("no credentials = %d", code)
	}
}

func TestPublicWebAccessAcceptsAConsolePassword(t *testing.T) {
	t.Setenv("DNSENTRY_ALLOW_PUBLIC_WEB", "1")
	t.Chdir(t.TempDir())
	config := &Config{HTTPListen: "0.0.0.0:18080"}
	err := checkWebExposure(config, "")
	if err == nil || !strings.Contains(err.Error(), "console password") {
		t.Fatalf("public access without any credential: %v", err)
	}
	store, openErr := auth.Open(authFilePath())
	if openErr != nil {
		t.Fatal(openErr)
	}
	if setErr := store.Set("admin", "correct horse"); setErr != nil {
		t.Fatal(setErr)
	}
	if err := checkWebExposure(config, ""); err != nil {
		t.Fatalf("a console password must allow public access: %v", err)
	}
}
