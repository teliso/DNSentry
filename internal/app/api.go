package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/teliso/DNSentry/internal/auth"
	"github.com/teliso/DNSentry/internal/services"
	"github.com/teliso/DNSentry/internal/upstream"

	"github.com/teliso/DNSentry/internal/buildinfo"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

// API serves the JSON management API under /api.
type API struct {
	ctx      context.Context // cancelled on shutdown; bounds background work
	apiToken string          // empty: loopback-only access

	resolver *DNSServer
	rules    *rules.Store
	cache    *cache.Cache
	logs     *querylog.Logger
	updater  *rules.Updater
	dnscrypt *DNSCryptService

	// configMu serialises configuration writes. saved is the configuration on
	// disk, which may differ from the running one in startup-only settings
	// awaiting a restart; nil until the first write.
	configMu sync.Mutex
	saved    *Config

	authFailures authThrottle
	auth         *auth.Store      // console login; opened on first use when nil
	webTLS       *webCertificates // nil when the console is served over plain HTTP
	sessions     *auth.Sessions   // browser sessions of that login
}

func newAPI(ctx context.Context, apiToken string, resolver *DNSServer, updater *rules.Updater, dnscrypt *DNSCryptService) *API {
	return &API{
		ctx:      ctx,
		apiToken: apiToken,
		sessions: auth.NewSessions(),
		resolver: resolver,
		rules:    resolver.rules,
		cache:    resolver.cache,
		logs:     resolver.logs,
		updater:  updater,
		dnscrypt: dnscrypt,
	}
}

type apiRoute struct {
	method  string
	path    string
	handler func(*API, http.ResponseWriter, *http.Request)
}

// apiRoutes is the complete JSON API surface, relative to /api.
var apiRoutes = []apiRoute{
	{http.MethodGet, "/status", (*API).getStatus},
	{http.MethodGet, "/config", (*API).getConfig},
	{http.MethodPut, "/config", (*API).updateConfig},
	{http.MethodGet, "/config/history", (*API).configHistory},
	{http.MethodPost, "/config/restore", (*API).restoreConfig},
	{http.MethodGet, "/config/export", (*API).exportConfig},
	{http.MethodPost, "/config/import", (*API).importConfig},
	{http.MethodGet, "/metrics", (*API).writeMetrics},
	{http.MethodPost, "/cache/clear", (*API).clearCache},
	{http.MethodPost, "/logs/clear", (*API).clearLogs},
	{http.MethodGet, "/stats", (*API).getStats},
	{http.MethodGet, "/services", (*API).listServices},
	{http.MethodPost, "/notifications/test", (*API).testNotification},
	{http.MethodPut, "/auth", (*API).setAuth},
	{http.MethodDelete, "/auth", (*API).deleteAuth},
	{http.MethodPost, "/protection", (*API).setProtection},
	{http.MethodPost, "/upstreams/test", (*API).testUpstreams},
	{http.MethodGet, "/rules", (*API).listRules},
	{http.MethodPost, "/rules", (*API).addRule},
	{http.MethodDelete, "/rules", (*API).deleteRule},
	{http.MethodGet, "/rules/check", (*API).checkRule},
	{http.MethodGet, "/rules/local", (*API).getLocalRules},
	{http.MethodPut, "/rules/local", (*API).putLocalRules},
	{http.MethodPost, "/reload", (*API).reloadRules},
	{http.MethodGet, "/sources", (*API).listSources},
	{http.MethodPut, "/sources", (*API).updateSources},
	{http.MethodPost, "/sources/refresh", (*API).refreshSources},
	{http.MethodGet, "/logs/export", (*API).exportLogs},
	{http.MethodGet, "/logs/days", (*API).listLogDays},
	{http.MethodGet, "/logs", (*API).listLogs},
}

// authorize enforces the API access policy and reports whether the request may
// proceed; on failure it has already written the response.
func (a *API) authorize(writer http.ResponseWriter, request *http.Request) bool {
	client := requestClientIP(request)
	// A live session is not a guess (256 random bits), so it is accepted even
	// while this address is throttled: behind a shared proxy address, somebody
	// else's failed attempts must not lock the administrator out.
	if a.sessionValid(request) {
		// The session cookie is SameSite=Strict; checking the origin as well
		// costs nothing and covers browsers that ignore the attribute.
		if mutatingAPIRequest(request) && !sameOriginMutation(request) {
			writeError(writer, http.StatusForbidden, "state-changing API requests require a same-origin request")
			return false
		}
		return true
	}
	if wait := a.authFailures.blocked(client); wait > 0 {
		writer.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(writer, http.StatusTooManyRequests, "too many failed authentication attempts")
		return false
	}
	loginSet := a.loginStore().Configured()
	if a.apiToken != "" {
		provided, ok := bearerToken(request)
		if ok && tokensEqual(provided, a.apiToken) {
			a.authFailures.succeed(client)
			return true
		}
		if ok {
			a.authFailures.fail(client)
		}
		writer.Header().Set("WWW-Authenticate", "Bearer")
		if loginSet {
			writeError(writer, http.StatusUnauthorized, "sign in or provide the API token")
		} else {
			writeError(writer, http.StatusUnauthorized, "invalid or missing API token")
		}
		return false
	}
	if loginSet {
		writeError(writer, http.StatusUnauthorized, "sign in required")
		return false
	}
	if !isLoopbackRequest(request) {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeError(writer, http.StatusUnauthorized, "API access requires a loopback request or configured token")
		return false
	}
	// Without a token the console trusts loopback callers, so a web page
	// must not be able to reach it through DNS rebinding (a public name that
	// resolves to 127.0.0.1). Browsers then send that name as the Host.
	if !loopbackHost(request.Host) {
		writeError(writer, http.StatusForbidden, "use http://localhost or an IP address to open the console, or set a console password or DNSENTRY_API_TOKEN")
		return false
	}
	if mutatingAPIRequest(request) && !sameOriginMutation(request) {
		writeError(writer, http.StatusForbidden, "state-changing API requests require a same-origin request")
		return false
	}
	return true
}

func (a *API) handle(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api")
	// Signing in has to work without being signed in.
	switch {
	case path == "/auth" && request.Method == http.MethodGet:
		a.getAuth(writer, request)
		return
	case path == "/login" && request.Method == http.MethodPost:
		a.login(writer, request)
		return
	case path == "/logout" && request.Method == http.MethodPost:
		a.logout(writer, request)
		return
	}
	if !a.authorize(writer, request) {
		return
	}
	for _, route := range apiRoutes {
		if route.path == path && route.method == request.Method {
			route.handler(a, writer, request)
			return
		}
	}
	writeError(writer, http.StatusNotFound, "not found")
}

func (a *API) getStatus(writer http.ResponseWriter, _ *http.Request) {
	config := a.resolver.configSnapshot()
	total, blocked := a.logs.Stats()
	dnscryptStatus := DNSCryptStatus{}
	if a.dnscrypt != nil {
		dnscryptStatus = a.dnscrypt.Status()
	}
	fallbackHealth := []upstream.Health{}
	if a.resolver.fallbackPool != nil {
		fallbackHealth = a.resolver.fallbackPool.Health()
	}
	a.configMu.Lock()
	pendingRestart := restartRequired(a.savedConfig(), config)
	a.configMu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{
		"version":                  buildinfo.String(),
		"config_path":              configPath(),
		"rules_file":               config.RulesFile,
		"restart_required":         pendingRestart,
		"web_tls":                  a.webTLS.Info(),
		"active_schedules":         activeSchedules(a.resolver),
		"server_time":              time.Now().Format(time.RFC3339),
		"protection":               a.resolver.protectionStatus(),
		"dns_listens":              config.DNSListens,
		"http_listen":              config.HTTPListen,
		"upstreams":                config.Upstreams,
		"fallback_upstreams":       config.FallbackUpstreams,
		"upstream_health":          a.resolver.pool.Health(),
		"upstream_routes":          a.resolver.routeStatus(),
		"fallback_upstream_health": fallbackHealth,
		"rule_sources":             a.updater.Sources(),
		"total_queries":            total,
		"blocked_queries":          blocked,
		"rules":                    a.rules.Len(),
		"local_rules":              a.rules.Counts()[rules.SourceLocal],
		"cache":                    a.cache.Stats(),
		"dnssec":                   a.resolver.DNSSECStats(),
		"security":                 a.logs.SecurityStats(),
		"dnscrypt":                 dnscryptStatus,
		"series":                   a.logs.Metrics(),
		"dashboard":                a.logs.Dashboard(),
	})
}

func (a *API) clearCache(writer http.ResponseWriter, _ *http.Request) {
	a.resolver.clearCache()
	writeJSON(writer, http.StatusOK, map[string]string{"status": "cleared"})
}

// listServices serves GET /services: the catalogue of blockable services.
func (a *API) listServices(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, services.Catalog)
}

// activeSchedules names the schedule windows that are open now (never null in JSON).
func activeSchedules(server *DNSServer) []string {
	if names := server.schedules.Load().Active(time.Now()); names != nil {
		return names
	}
	return []string{}
}

// getStats serves GET /stats?range=24h|7d|30d|90d: queries and blocked counts
// per hour (24h) or per day, kept across restarts.
func (a *API) getStats(writer http.ResponseWriter, request *http.Request) {
	window := request.URL.Query().Get("range")
	if window == "" {
		window = "24h"
	}
	if window != "24h" && window != "7d" && window != "30d" && window != "90d" {
		writeError(writer, http.StatusBadRequest, "range must be 24h, 7d, 30d or 90d")
		return
	}
	writeJSON(writer, http.StatusOK, a.logs.History(window))
}

// clearLogs serves POST /logs/clear: empties the in-memory query log.
func (a *API) clearLogs(writer http.ResponseWriter, _ *http.Request) {
	a.logs.Clear()
	writeJSON(writer, http.StatusOK, map[string]string{"status": "cleared"})
}

// listLogs serves GET /logs?search=&action=&offset=&limit= (the recent
// in-memory log) and, with date=YYYY-MM-DD, a day saved on disk.
func (a *API) listLogs(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	filter := querylog.Filter{Search: query.Get("search"), Action: query.Get("action"), Offset: offset, Limit: limit}
	if day := query.Get("date"); day != "" {
		page, err := a.logs.QueryHistory(day, filter)
		if !writeHistoryError(writer, err) {
			return
		}
		writeJSON(writer, http.StatusOK, page)
		return
	}
	writeJSON(writer, http.StatusOK, a.logs.Query(filter))
}

// writeHistoryError reports a failed saved-log read and returns whether there was none.
func writeHistoryError(writer http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, querylog.ErrNoHistory):
		writeError(writer, http.StatusNotFound, err.Error())
	case errors.Is(err, querylog.ErrBadDate):
		writeError(writer, http.StatusBadRequest, err.Error())
	default:
		writeError(writer, http.StatusInternalServerError, "could not read the saved log")
	}
	return false
}

// listLogDays serves GET /logs/days: whether logs are saved to disk and which days exist.
func (a *API) listLogDays(writer http.ResponseWriter, _ *http.Request) {
	days := a.logs.HistoryDays()
	if days == nil {
		days = []string{}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"enabled": a.resolver.configSnapshot().QueryLogEnabled, "days": days})
}
