package app

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/querylog"
)

const maxConfigImportBytes = 1 << 20

func attachment(writer http.ResponseWriter, contentType, name string) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	writer.Header().Set("Cache-Control", "no-store")
}

// csvSafe stops spreadsheets from running a cell as a formula.
func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// exportLogs serves GET /logs/export?format=csv|json&search=&action=: every
// in-memory log entry that matches the filter, as a download.
func (a *API) exportLogs(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	filter := querylog.Filter{Search: query.Get("search"), Action: query.Get("action")}
	entries := a.logs.Export(filter)
	if day := query.Get("date"); day != "" {
		var err error
		if entries, err = a.logs.ExportHistory(day, filter); !writeHistoryError(writer, err) {
			return
		}
	}
	stamp := time.Now().Format("20060102-150405")
	switch format := query.Get("format"); format {
	case "", "csv":
		attachment(writer, "text/csv; charset=utf-8", "dnsentry-logs-"+stamp+".csv")
		out := csv.NewWriter(writer)
		_ = out.Write([]string{"time", "client", "domain", "type", "action", "upstream", "duration_ms", "rule", "rule_source"})
		for _, entry := range entries {
			_ = out.Write([]string{csvSafe(entry.Time), csvSafe(entry.Client), csvSafe(entry.Domain), csvSafe(entry.Type), csvSafe(entry.Action), csvSafe(entry.Upstream), strconv.FormatInt(entry.Duration, 10), csvSafe(entry.Rule), csvSafe(entry.RuleSource)})
		}
		out.Flush()
	case "json":
		attachment(writer, "application/json", "dnsentry-logs-"+stamp+".json")
		_ = json.NewEncoder(writer).Encode(entries)
	default:
		writeError(writer, http.StatusBadRequest, "format must be csv or json")
	}
}

// exportConfig serves GET /config/export: the saved configuration file as it is
// on disk. It contains secrets (private keys), so it is only sent as a download.
func (a *API) exportConfig(writer http.ResponseWriter, _ *http.Request) {
	a.configMu.Lock()
	data, err := os.ReadFile(configPath())
	a.configMu.Unlock()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not read the configuration file")
		return
	}
	attachment(writer, "application/yaml; charset=utf-8", "dnsentry-config-"+time.Now().Format("20060102-150405")+".yaml")
	_, _ = writer.Write(data)
}

// importConfig serves POST /config/import with a configuration file as the body.
// It is validated and applied exactly like a configuration saved from the
// console (including the restriction on paths), and recorded in the history.
func (a *API) importConfig(writer http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxConfigImportBytes))
	if err != nil {
		writeError(writer, http.StatusRequestEntityTooLarge, "configuration file is too large")
		return
	}
	fileConfig := new(yamlConfig)
	if err := yaml.Unmarshal(data, fileConfig); err != nil {
		writeError(writer, http.StatusBadRequest, "not a valid configuration file: "+err.Error())
		return
	}
	next := fileConfig.toConfig()
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if err := checkAPIPaths(*next, a.savedConfig()); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	a.commitConfig(writer, next)
}
