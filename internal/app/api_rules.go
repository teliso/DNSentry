package app

import (
	"context"
	"net/http"

	"github.com/teliso/DNSentry/internal/rules"
)

func (a *API) listRules(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, a.rules.List())
}

func (a *API) reloadRules(writer http.ResponseWriter, _ *http.Request) {
	if err := a.rules.Reload(); err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	a.resolver.clearCache()
	writeJSON(writer, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (a *API) listSources(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, a.updater.Sources())
}

func (a *API) addRule(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Domain string       `json:"domain"`
		Action rules.Action `json:"action"`
	}
	if !decodeJSON(writer, request, &input, "invalid JSON") {
		return
	}
	if err := a.rules.Add(input.Domain, input.Action); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *API) deleteRule(writer http.ResponseWriter, request *http.Request) {
	domain := request.URL.Query().Get("domain")
	action := rules.Action(request.URL.Query().Get("action"))
	if err := a.rules.Delete(domain, action); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) updateSources(writer http.ResponseWriter, request *http.Request) {
	var sources []rules.Source
	if !decodeJSON(writer, request, &sources, "invalid rule sources") {
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	a.updater.SetSources(sources)
	a.refreshRuleSources()
	next := a.savedConfig()
	next.RuleSources = a.updater.Sources()
	if err := saveConfig(&next); err != nil {
		writeError(writer, http.StatusInternalServerError, "could not save rule sources: "+err.Error())
		return
	}
	a.saved = &next
	writeJSON(writer, http.StatusOK, a.updater.Sources())
}

// refreshRuleSources downloads new or re-enabled sources in the background.
func (a *API) refreshRuleSources() {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go a.updater.RefreshDue(ctx)
}
