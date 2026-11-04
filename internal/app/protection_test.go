package app

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/teliso/DNSentry/internal/upstream"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
)

func TestPausedProtectionSkipsFilterRules(t *testing.T) {
	dir := t.TempDir()
	ruleFile := dir + "/rules.txt"
	if err := os.WriteFile(ruleFile, []byte("||ads.test^\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := rules.NewStore(ruleFile)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	upstreamServer, _ := startAnswerServer(t, net.IPv4(203, 0, 113, 7))
	config := &Config{Upstreams: []string{upstreamServer}, BlockingMode: "nxdomain", CacheSize: 1 << 20}
	server := &DNSServer{
		config: config, rules: store, cache: cache.New(config.CacheSize, false), logs: querylog.New(10),
		client: &dns.Client{Net: "udp", Timeout: time.Second}, pool: upstream.NewPool(config.Upstreams),
	}
	query := func() *dns.Msg {
		writer := new(captureResponseWriter)
		server.ServeDNS(writer, newTestRequest("ads.test.", dns.TypeA))
		return writer.response
	}

	if response := query(); response == nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("filtering on: want NXDOMAIN, got %v", response)
	}
	server.pauseProtection(time.Hour)
	if status := server.protectionStatus(); status.Enabled || status.ResumeAt == "" {
		t.Fatalf("timed pause status = %#v", status)
	}
	if response := query(); response == nil || len(response.Answer) != 1 {
		t.Fatalf("filtering paused: want an upstream answer, got %v", response)
	}
	server.resumeProtection()
	if response := query(); response == nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("filtering resumed: want NXDOMAIN, got %v", response)
	}

	server.pauseProtection(0)
	if status := server.protectionStatus(); status.Enabled || status.ResumeAt != "" {
		t.Fatalf("indefinite pause status = %#v", status)
	}
	server.protectionPausedUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if !server.protectionStatus().Enabled {
		t.Fatal("an elapsed pause must re-enable filtering")
	}
}

func TestProtectionAPI(t *testing.T) {
	api := newConfigTestAPI(t)
	response := callAPI(t, api, http.MethodPost, "/api/protection", map[string]any{"enabled": false, "duration_minutes": 5})
	var status ProtectionStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.Enabled || status.ResumeAt == "" {
		t.Fatalf("pause = %d %s", response.Code, response.Body)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/protection", map[string]any{"enabled": false, "duration_minutes": 100000}); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized pause = %d", response.Code)
	}
	response = callAPI(t, api, http.MethodPost, "/api/protection", map[string]any{"enabled": true})
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || !status.Enabled {
		t.Fatalf("resume = %d %s", response.Code, response.Body)
	}
}
