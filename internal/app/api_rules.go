package app

import (
	"context"
	"encoding/json"
	"net/http"
)

func (a *API) addRule(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Domain string     `json:"domain"`
		Action RuleAction `json:"action"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := a.rules.Add(input.Domain, input.Action); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *API) deleteRule(writer http.ResponseWriter, request *http.Request) {
	domain := request.URL.Query().Get("domain")
	action := RuleAction(request.URL.Query().Get("action"))
	if err := a.rules.Delete(domain, action); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) updateSources(writer http.ResponseWriter, request *http.Request) {
	var sources []RuleSource
	if err := json.NewDecoder(request.Body).Decode(&sources); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid rule sources"})
		return
	}
	a.updater.SetSources(sources)
	config := a.resolver.configSnapshot()
	config.RuleSources = a.updater.Sources()
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go a.updater.RefreshNow(ctx)
	if err := saveConfig(&config); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "could not save rule sources"})
		return
	}
	a.resolver.updateConfig(config)
	writeJSON(writer, http.StatusOK, config.RuleSources)
}
