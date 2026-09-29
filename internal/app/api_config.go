package app

import (
	"fmt"
	"net/http"
	"path/filepath"
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

// restartRequired reports whether saved differs from running in settings that
// are only read at startup (listeners, rules file, query log, encrypted DNS).
func restartRequired(saved, running Config) bool {
	return !slices.Equal(saved.DNSListens, running.DNSListens) ||
		saved.HTTPListen != running.HTTPListen ||
		saved.RulesFile != running.RulesFile ||
		queryLogSettingsChanged(saved, running) ||
		!encryptionConfigEqual(saved.Encryption, running.Encryption)
}

func queryLogSettingsChanged(next, current Config) bool {
	return next.QueryLogSize != current.QueryLogSize ||
		next.QueryLogEnabled != current.QueryLogEnabled ||
		next.QueryLogFile != current.QueryLogFile ||
		next.QueryLogRetentionDays != current.QueryLogRetentionDays
}

// withRunningStartupSettings returns config with the startup-only settings of
// running, i.e. the part of config that can be applied without a restart.
func withRunningStartupSettings(config, running Config) Config {
	config.DNSListen, config.DNSListens = running.DNSListen, running.DNSListens
	config.HTTPListen = running.HTTPListen
	config.RulesFile = running.RulesFile
	config.QueryLogSize, config.QueryLogEnabled = running.QueryLogSize, running.QueryLogEnabled
	config.QueryLogFile, config.QueryLogRetentionDays = running.QueryLogFile, running.QueryLogRetentionDays
	config.Encryption = running.Encryption
	return config
}

// savedConfig is the configuration on disk. It equals the running
// configuration except for startup-only settings that await a restart.
func (a *API) savedConfig() Config {
	if a.saved != nil {
		return *a.saved
	}
	return a.resolver.configSnapshot()
}

// configResponse is the body of GET/PUT /config and POST /config/restore.
func (a *API) configResponse() Config {
	config := publicConfig(a.savedConfig())
	config.RuleSources = a.updater.Sources()
	return config
}

// commitConfig validates, persists and applies next. Everything that can change
// at runtime takes effect immediately; startup-only settings are saved and
// reported through restart_required in /api/status.
func (a *API) commitConfig(writer http.ResponseWriter, next *Config) {
	validated, err := validateConfig(next)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if err := saveConfig(validated); err != nil {
		writeError(writer, http.StatusInternalServerError, "could not save config: "+err.Error())
		return
	}
	a.saved = validated
	a.updater.SetSources(validated.RuleSources)
	a.refreshRuleSources()
	if err := a.resolver.applyConfig(withRunningStartupSettings(*validated, a.resolver.configSnapshot())); err != nil {
		writeError(writer, http.StatusInternalServerError, "config was saved but could not be applied: "+err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, a.configResponse())
}

func (a *API) getConfig(writer http.ResponseWriter, _ *http.Request) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	writeJSON(writer, http.StatusOK, a.configResponse())
}

func (a *API) updateConfig(writer http.ResponseWriter, request *http.Request) {
	var next Config
	if !decodeJSON(writer, request, &next, "invalid config JSON") {
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	saved := a.savedConfig()
	// Secrets are never sent to the browser; an empty value means "keep".
	if next.Encryption.PrivateKeyPEM == "" {
		next.Encryption.PrivateKeyPEM = saved.Encryption.PrivateKeyPEM
	}
	if next.Encryption.DNSCrypt.PrivateKey == "" {
		next.Encryption.DNSCrypt.PrivateKey = saved.Encryption.DNSCrypt.PrivateKey
	}
	if next.Encryption.DNSCrypt.ResolverSecret == "" {
		next.Encryption.DNSCrypt.ResolverSecret = saved.Encryption.DNSCrypt.ResolverSecret
	}
	if err := checkAPIPaths(next, saved); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	// Rule sources are managed through /api/sources; a config form that was
	// loaded earlier must not roll them back.
	next.RuleSources = a.updater.Sources()
	a.commitConfig(writer, &next)
}

func (a *API) restoreConfig(writer http.ResponseWriter, _ *http.Request) {
	restored, err := loadConfigBackup()
	if err != nil {
		writeError(writer, http.StatusNotFound, "no valid configuration backup: "+err.Error())
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	a.commitConfig(writer, restored)
}

// checkAPIPaths limits file paths that can be set through the API. The
// service reads or writes these files with its own privileges, so a client
// holding the API token must not be able to point them anywhere on disk: a
// changed path has to be relative and stay inside the working directory.
// Absolute paths (e.g. /etc/ssl/...) remain possible by editing the
// configuration file, and unchanged values are always accepted.
func checkAPIPaths(next, saved Config) error {
	for _, field := range []struct {
		name        string
		next, saved string
	}{
		{"rules_file", next.RulesFile, saved.RulesFile},
		{"query_log_file", next.QueryLogFile, saved.QueryLogFile},
		{"dnssec_trust_anchor_file", next.DNSSECTrustAnchorFile, saved.DNSSECTrustAnchorFile},
		{"encryption.certificate", next.Encryption.Certificate, saved.Encryption.Certificate},
		{"encryption.private_key", next.Encryption.PrivateKey, saved.Encryption.PrivateKey},
	} {
		if field.next == "" || field.next == field.saved {
			continue
		}
		clean := filepath.Clean(field.next)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s must be a relative path inside the working directory; edit the configuration file to use %q", field.name, field.next)
		}
	}
	return nil
}
