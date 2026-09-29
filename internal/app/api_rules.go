package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/teliso/DNSentry/internal/rules"
)

// Filter rules are evaluated before the DNS cache, so rule changes take effect
// for the next query without clearing it.

func ruleError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rules.ErrInvalidRule):
		writeError(writer, http.StatusBadRequest, err.Error())
	case errors.Is(err, rules.ErrRuleExists):
		writeError(writer, http.StatusConflict, err.Error())
	case errors.Is(err, rules.ErrRuleMissing), errors.Is(err, rules.ErrUnknownSource):
		writeError(writer, http.StatusNotFound, err.Error())
	default:
		writeError(writer, http.StatusInternalServerError, err.Error())
	}
}

// listRules serves GET /rules?search=&action=&source=&offset=&limit=.
func (a *API) listRules(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	writeJSON(writer, http.StatusOK, a.rules.Query(rules.Filter{
		Search: query.Get("search"),
		Action: rules.Action(query.Get("action")),
		Source: query.Get("source"),
		Offset: offset,
		Limit:  limit,
	}))
}

func (a *API) checkRule(writer http.ResponseWriter, request *http.Request) {
	result, err := a.rules.Check(request.URL.Query().Get("domain"))
	if err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (a *API) addRule(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Domain string       `json:"domain"`
		Action rules.Action `json:"action"`
	}
	if !decodeJSON(writer, request, &input, "invalid JSON") {
		return
	}
	entry, err := a.rules.Add(input.Domain, input.Action)
	if err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, entry)
}

func (a *API) deleteRule(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if err := a.rules.Delete(query.Get("domain"), rules.Action(query.Get("action"))); err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) getLocalRules(writer http.ResponseWriter, _ *http.Request) {
	text, err := a.rules.LocalText()
	if err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"text": text})
}

func (a *API) putLocalRules(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Text string `json:"text"`
	}
	if !decodeJSON(writer, request, &input, "invalid JSON") {
		return
	}
	summary, err := a.rules.SetLocalText(input.Text)
	if err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, summary)
}

func (a *API) reloadRules(writer http.ResponseWriter, _ *http.Request) {
	if err := a.rules.Reload(); err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (a *API) listSources(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, a.updater.Sources())
}

func (a *API) updateSources(writer http.ResponseWriter, request *http.Request) {
	var sources []rules.Source
	if !decodeJSON(writer, request, &sources, "invalid rule sources") {
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if err := a.updater.SetSources(sources); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
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

// refreshSources serves POST /sources/refresh {"url": ""}; an empty URL
// refreshes every enabled source. Downloads run in the background.
func (a *API) refreshSources(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		URL string `json:"url"`
	}
	if !decodeJSON(writer, request, &input, "invalid JSON") {
		return
	}
	if err := a.updater.StartRefresh(a.context(), input.URL); err != nil {
		ruleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, a.updater.Sources())
}

// refreshRuleSources downloads new or re-enabled sources in the background.
func (a *API) refreshRuleSources() {
	go a.updater.RefreshDue(a.context())
}

func (a *API) context() context.Context {
	if a.ctx == nil {
		return context.Background()
	}
	return a.ctx
}
