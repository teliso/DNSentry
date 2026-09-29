package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"

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
}

func newAPI(ctx context.Context, apiToken string, resolver *DNSServer, updater *rules.Updater, dnscrypt *DNSCryptService) *API {
	return &API{
		ctx:      ctx,
		apiToken: apiToken,
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
	{http.MethodPost, "/config/restore", (*API).restoreConfig},
	{http.MethodGet, "/metrics", (*API).writeMetrics},
	{http.MethodPost, "/cache/clear", (*API).clearCache},
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
	{http.MethodGet, "/logs", (*API).listLogs},
}

// authorize enforces the API access policy and reports whether the request may
// proceed; on failure it has already written the response.
func (a *API) authorize(writer http.ResponseWriter, request *http.Request) bool {
	client := requestClientIP(request)
	if wait := a.authFailures.blocked(client); wait > 0 {
		writer.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(writer, http.StatusTooManyRequests, "too many failed authentication attempts")
		return false
	}
	if a.apiToken == "" {
		if !isLoopbackRequest(request) {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeError(writer, http.StatusUnauthorized, "API access requires a loopback request or configured token")
			return false
		}
		// Without a token the console trusts loopback callers, so a web page
		// must not be able to reach it through DNS rebinding (a public name that
		// resolves to 127.0.0.1). Browsers then send that name as the Host.
		if !loopbackHost(request.Host) {
			writeError(writer, http.StatusForbidden, "use http://localhost or an IP address to open the console, or configure DNSENTRY_API_TOKEN")
			return false
		}
		if mutatingAPIRequest(request) && !sameOriginMutation(request) {
			writeError(writer, http.StatusForbidden, "state-changing API requests require a same-origin request")
			return false
		}
		return true
	}
	provided, ok := bearerToken(request)
	if !ok || !tokensEqual(provided, a.apiToken) {
		if ok {
			a.authFailures.fail(client)
		}
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeError(writer, http.StatusUnauthorized, "invalid or missing API token")
		return false
	}
	a.authFailures.succeed(client)
	return true
}

func (a *API) handle(writer http.ResponseWriter, request *http.Request) {
	if !a.authorize(writer, request) {
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/api")
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
	fallbackHealth := []UpstreamHealth{}
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
		"dns_listen":               config.DNSListen,
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

// listLogs serves GET /logs?search=&action=&offset=&limit=.
func (a *API) listLogs(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	writeJSON(writer, http.StatusOK, a.logs.Query(querylog.Filter{
		Search: query.Get("search"),
		Action: query.Get("action"),
		Offset: offset,
		Limit:  limit,
	}))
}
