package app

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

func publicConfig(config Config) Config {
	public := config
	public.Encryption.PrivateKeyPEM = ""
	public.Encryption.DNSCrypt.PrivateKey = ""
	public.Encryption.DNSCrypt.ResolverSecret = ""
	return public
}

func (a *API) restoreConfig(writer http.ResponseWriter) {
	restored, err := loadConfigBackup()
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "no valid configuration backup: " + err.Error()})
		return
	}
	current := a.resolver.configSnapshot()
	restartRequired := !slices.Equal(restored.DNSListens, current.DNSListens) || restored.HTTPListen != current.HTTPListen || restored.RulesFile != current.RulesFile || queryLogSettingsChanged(*restored, current)
	encryptionChanged := !encryptionConfigEqual(restored.Encryption, current.Encryption)
	if err := saveConfig(restored); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "could not restore config: " + err.Error()})
		return
	}
	if restartRequired || encryptionChanged {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "configuration restored but some settings require a restart", "restart_required": true, "config": publicConfig(*restored)})
		return
	}
	a.updater.SetSources(restored.RuleSources)
	restored.RuleSources = a.updater.Sources()
	if err := a.resolver.applyConfig(*restored); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "could not apply restored config: " + err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, publicConfig(*restored))
}

func queryLogSettingsChanged(next, current Config) bool {
	return next.QueryLogSize != current.QueryLogSize ||
		next.QueryLogEnabled != current.QueryLogEnabled ||
		next.QueryLogFile != current.QueryLogFile ||
		next.QueryLogRetentionDays != current.QueryLogRetentionDays
}

func (a *API) updateConfig(writer http.ResponseWriter, request *http.Request) {
	var next Config
	if err := json.NewDecoder(request.Body).Decode(&next); err != nil || (strings.TrimSpace(next.DNSListen) == "" && len(next.DNSListens) == 0) || strings.TrimSpace(next.HTTPListen) == "" || len(next.Upstreams) == 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid config"})
		return
	}
	current := a.resolver.configSnapshot()
	if next.Encryption.PrivateKeyPEM == "" {
		next.Encryption.PrivateKeyPEM = current.Encryption.PrivateKeyPEM
	}
	if next.Encryption.DNSCrypt.PrivateKey == "" {
		next.Encryption.DNSCrypt.PrivateKey = current.Encryption.DNSCrypt.PrivateKey
	}
	if next.Encryption.DNSCrypt.ResolverSecret == "" {
		next.Encryption.DNSCrypt.ResolverSecret = current.Encryption.DNSCrypt.ResolverSecret
	}
	validated, err := validateConfig(&next)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	next = *validated
	for index, upstream := range next.Upstreams {
		next.Upstreams[index] = normalizeUpstream(upstream)
	}
	for index, bootstrap := range next.BootstrapDNS {
		next.BootstrapDNS[index] = normalizeUpstream(bootstrap)
	}
	if next.UpstreamTimeout <= 0 {
		next.UpstreamTimeout = 4
	}
	if len(next.BootstrapDNS) == 0 {
		next.BootstrapDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	restartRequired := !slices.Equal(next.DNSListens, current.DNSListens) || next.HTTPListen != current.HTTPListen || next.RulesFile != current.RulesFile || queryLogSettingsChanged(next, current)
	encryptionChanged := !encryptionConfigEqual(next.Encryption, current.Encryption)
	if err := saveConfig(&next); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "could not save config"})
		return
	}
	if restartRequired || encryptionChanged {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "configuration was saved but requires a restart", "restart_required": true, "config": publicConfig(next)})
		return
	}
	a.updater.SetSources(next.RuleSources)
	next.RuleSources = a.updater.Sources()
	if err := a.resolver.applyConfig(next); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "could not apply config: " + err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, publicConfig(next))
}
