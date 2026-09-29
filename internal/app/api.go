package app

import (
	"context"
	"net/http"
	"strings"
)

type API struct {
	rules    *RuleStore
	cache    *DNSCache
	logs     *QueryLogger
	resolver *DNSServer
	updater  *RuleUpdater
	dnscrypt *DNSCryptService
	apiToken string
	ctx      context.Context
}

func newAPI(rules *RuleStore, cache *DNSCache, logs *QueryLogger, resolver *DNSServer, updater *RuleUpdater, dnscryptServices ...*DNSCryptService) *API {
	api := &API{rules: rules, cache: cache, logs: logs, resolver: resolver, updater: updater}
	if len(dnscryptServices) > 0 {
		api.dnscrypt = dnscryptServices[0]
	}
	return api
}

func (a *API) handle(writer http.ResponseWriter, request *http.Request) {
	if a.apiToken == "" {
		if !isLoopbackRequest(request) {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "API access requires a loopback request or configured token"})
			return
		}
	} else {
		provided, ok := bearerToken(request)
		if !ok || !tokensEqual(provided, a.apiToken) {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid or missing API token"})
			return
		}
	}

	path := strings.TrimPrefix(request.URL.Path, "/api")
	if a.apiToken == "" && mutatingAPIRequest(request) && !sameOriginMutation(request) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "state-changing API requests require a same-origin request"})
		return
	}
	switch {
	case path == "/status" && request.Method == http.MethodGet:
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
		writeJSON(writer, http.StatusOK, map[string]any{"dns_listen": config.DNSListen, "dns_listens": config.DNSListens, "http_listen": config.HTTPListen, "upstreams": config.Upstreams, "fallback_upstreams": config.FallbackUpstreams, "upstream_health": a.resolver.pool.Health(), "fallback_upstream_health": fallbackHealth, "rule_sources": a.updater.Sources(), "total_queries": total, "blocked_queries": blocked, "rules": len(a.rules.List()), "cache": a.cache.Stats(), "dnssec": a.resolver.DNSSECStats(), "security": a.logs.SecurityStats(), "dnscrypt": dnscryptStatus, "series": a.logs.Metrics(), "dashboard": a.logs.Dashboard()})
	case path == "/config" && request.Method == http.MethodGet:
		config := a.resolver.configSnapshot()
		writeJSON(writer, http.StatusOK, publicConfig(config))
	case path == "/config" && request.Method == http.MethodPut:
		a.updateConfig(writer, request)
	case path == "/config/restore" && request.Method == http.MethodPost:
		a.restoreConfig(writer)
	case path == "/metrics" && request.Method == http.MethodGet:
		a.writeMetrics(writer)
	case path == "/cache/clear" && request.Method == http.MethodPost:
		a.resolver.clearCache()
		writeJSON(writer, http.StatusOK, map[string]string{"status": "cleared"})
	case path == "/upstreams/test" && request.Method == http.MethodPost:
		a.testUpstreams(writer, request)
	case path == "/rules" && request.Method == http.MethodGet:
		writeJSON(writer, http.StatusOK, a.rules.List())
	case path == "/sources" && request.Method == http.MethodGet:
		writeJSON(writer, http.StatusOK, a.updater.Sources())
	case path == "/sources" && request.Method == http.MethodPut:
		a.updateSources(writer, request)
	case path == "/rules" && request.Method == http.MethodPost:
		a.addRule(writer, request)
	case path == "/rules" && request.Method == http.MethodDelete:
		a.deleteRule(writer, request)
	case path == "/reload" && request.Method == http.MethodPost:
		if err := a.rules.Reload(); err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.resolver.clearCache()
		writeJSON(writer, http.StatusOK, map[string]string{"status": "reloaded"})
	case path == "/logs" && request.Method == http.MethodGet:
		writeJSON(writer, http.StatusOK, a.logs.List())
	default:
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}
