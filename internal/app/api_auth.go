package app

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/teliso/DNSentry/internal/auth"
)

const (
	sessionCookie = "dnsentry_session"
	sessionTTL    = 7 * 24 * time.Hour
)

// authFilePath is where the console login is stored, next to the configuration.
func authFilePath() string { return filepath.Join(filepath.Dir(configPath()), "auth.json") }

// loginStore returns the credential store, opening it on first use.
func (a *API) loginStore() *auth.Store {
	if a.auth == nil {
		a.auth, _ = auth.Open(authFilePath())
		if a.auth == nil {
			a.auth = &auth.Store{}
		}
	}
	return a.auth
}

func (a *API) sessionValid(request *http.Request) bool {
	cookie, err := request.Cookie(sessionCookie)
	return err == nil && a.sessions.Valid(cookie.Value)
}

func (a *API) startSession(writer http.ResponseWriter, request *http.Request) error {
	token, err := a.sessions.New(sessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(writer, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsHTTPS(request),
	})
	return nil
}

func clearSessionCookie(writer http.ResponseWriter, request *http.Request) {
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsHTTPS(request)})
}

// requestIsHTTPS is true for a TLS connection, and for a plain one that comes
// from a reverse proxy on this machine saying the client used HTTPS. The header
// is trusted only from loopback: anybody else could simply claim it.
func requestIsHTTPS(request *http.Request) bool {
	if request.TLS != nil {
		return true
	}
	return isLoopbackRequest(request) && strings.EqualFold(strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")), "https")
}

// authenticated reports whether the request would pass authorize, without any
// side effects (no throttling, no response).
func (a *API) authenticated(request *http.Request) bool {
	if a.sessionValid(request) {
		return true
	}
	if a.apiToken != "" {
		provided, ok := bearerToken(request)
		return ok && tokensEqual(provided, a.apiToken)
	}
	return !a.loginStore().Configured() && isLoopbackRequest(request) && loopbackHost(request.Host)
}

type authStatus struct {
	Configured    bool   `json:"configured"`     // a console password is set
	TokenRequired bool   `json:"token_required"` // DNSENTRY_API_TOKEN is set
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
}

func (a *API) currentAuthStatus(request *http.Request) authStatus {
	store := a.loginStore()
	status := authStatus{Configured: store.Configured(), TokenRequired: a.apiToken != "", Authenticated: a.authenticated(request)}
	if status.Configured && status.Authenticated {
		status.Username = store.Username()
	}
	return status
}

// signedInStatus is the answer after a successful sign-in or password change.
func (a *API) signedInStatus() authStatus {
	store := a.loginStore()
	return authStatus{Configured: store.Configured(), TokenRequired: a.apiToken != "", Authenticated: true, Username: store.Username()}
}

// getAuth serves GET /auth. It needs no authorization: the console asks it
// which way to sign in.
func (a *API) getAuth(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, http.StatusOK, a.currentAuthStatus(request))
}

// login serves POST /login with {"username", "password"} and starts a session.
func (a *API) login(writer http.ResponseWriter, request *http.Request) {
	client := requestClientIP(request)
	if wait := a.authFailures.blocked(client); wait > 0 {
		writer.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(writer, http.StatusTooManyRequests, "too many failed sign-in attempts")
		return
	}
	if !sameOriginMutation(request) {
		writeError(writer, http.StatusForbidden, "sign-in requires a same-origin request")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(writer, request, &input, "invalid sign-in request") {
		return
	}
	store := a.loginStore()
	if !store.Configured() {
		writeError(writer, http.StatusBadRequest, "no console password is set")
		return
	}
	if !store.Verify(input.Username, input.Password) {
		a.authFailures.fail(client)
		writeError(writer, http.StatusUnauthorized, "wrong username or password")
		return
	}
	a.authFailures.succeed(client)
	if err := a.startSession(writer, request); err != nil {
		writeError(writer, http.StatusInternalServerError, "could not start a session")
		return
	}
	writeJSON(writer, http.StatusOK, a.signedInStatus())
}

// logout serves POST /logout.
func (a *API) logout(writer http.ResponseWriter, request *http.Request) {
	if !sameOriginMutation(request) {
		writeError(writer, http.StatusForbidden, "sign-out requires a same-origin request")
		return
	}
	if cookie, err := request.Cookie(sessionCookie); err == nil {
		a.sessions.Revoke(cookie.Value)
	}
	clearSessionCookie(writer, request)
	writeJSON(writer, http.StatusOK, map[string]string{"status": "signed out"})
}

// setAuth serves PUT /auth with {"username", "password", "current_password"}:
// it sets or changes the console login. Changing an existing password needs the
// current one, and signs every other browser out.
func (a *API) setAuth(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
	}
	if !decodeJSON(writer, request, &input, "invalid request") {
		return
	}
	store := a.loginStore()
	if store.Configured() && !a.currentPasswordOK(writer, request, store, input.CurrentPassword) {
		return
	}
	if err := store.Set(input.Username, input.Password); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	a.sessions.RevokeAll()
	if err := a.startSession(writer, request); err != nil {
		writeError(writer, http.StatusInternalServerError, "could not start a session")
		return
	}
	writeJSON(writer, http.StatusOK, a.signedInStatus())
}

// deleteAuth serves DELETE /auth with {"current_password"}: it turns the login off.
func (a *API) deleteAuth(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
	}
	if !decodeJSON(writer, request, &input, "invalid request") {
		return
	}
	store := a.loginStore()
	if !store.Configured() {
		writeJSON(writer, http.StatusOK, a.currentAuthStatus(request))
		return
	}
	if !a.currentPasswordOK(writer, request, store, input.CurrentPassword) {
		return
	}
	if err := store.Clear(); err != nil {
		writeError(writer, http.StatusInternalServerError, "could not remove the login: "+err.Error())
		return
	}
	a.sessions.RevokeAll()
	clearSessionCookie(writer, request)
	writeJSON(writer, http.StatusOK, authStatus{TokenRequired: a.apiToken != "", Authenticated: a.apiToken == "" && isLoopbackRequest(request)})
}

// currentPasswordOK checks the password a signed-in user must repeat before
// changing or removing the login, counting wrong guesses like failed sign-ins.
func (a *API) currentPasswordOK(writer http.ResponseWriter, request *http.Request, store *auth.Store, password string) bool {
	client := requestClientIP(request)
	if wait := a.authFailures.blocked(client); wait > 0 {
		writer.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(writer, http.StatusTooManyRequests, "too many failed attempts")
		return false
	}
	if !store.VerifyPassword(password) {
		a.authFailures.fail(client)
		writeError(writer, http.StatusForbidden, "the current password is wrong")
		return false
	}
	a.authFailures.succeed(client)
	return true
}
