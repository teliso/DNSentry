package querylog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teliso/DNSentry/internal/rules"
)

func TestPersistentQueryLoggerWritesJSONLAndCloses(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "querylog")
	logger, err := NewWithPersistence(10, PersistenceConfig{Enabled: true, File: prefix, RetentionDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Time: time.Now().Format(time.RFC3339), Client: "192.0.2.1", Domain: "example.test", Type: "A", Action: "forwarded", Duration: 4}
	logger.Add(entry)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filePath(prefix, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("JSONL lines = %d, want 1", len(lines))
	}
	var written Entry
	if err := json.Unmarshal([]byte(lines[0]), &written); err != nil {
		t.Fatal(err)
	}
	if written != entry {
		t.Fatalf("written entry = %#v, want %#v", written, entry)
	}
}

func TestPersistentQueryLoggerLoadsRecentEntries(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "querylog")
	path := filePath(prefix, time.Now())
	entries := []Entry{
		{Time: time.Now().Format(time.RFC3339), Domain: "first.test", Type: "A", Action: "forwarded"},
		{Time: time.Now().Format(time.RFC3339), Domain: "second.test", Type: "AAAA", Action: "cached"},
		{Time: time.Now().Format(time.RFC3339), Domain: "third.test", Type: "TXT", Action: "block"},
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	logger, err := NewWithPersistence(2, PersistenceConfig{Enabled: true, File: prefix, RetentionDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	loaded := logger.List()
	if len(loaded) != 2 || loaded[0].Domain != "third.test" || loaded[1].Domain != "second.test" {
		t.Fatalf("loaded entries = %#v", loaded)
	}
}

func TestPersistentQueryLoggerCleansExpiredFiles(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "querylog")
	now := time.Now()
	expired := filePath(prefix, now.AddDate(0, 0, -2))
	retained := filePath(prefix, now.AddDate(0, 0, -1))
	for _, path := range []string{expired, retained} {
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	logger, err := NewWithPersistence(10, PersistenceConfig{Enabled: true, File: prefix, RetentionDays: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Fatalf("expired log was not removed: %v", err)
	}
	if _, err := os.Stat(retained); err != nil {
		t.Fatalf("retained log was removed: %v", err)
	}
}

func TestQueryLoggerDashboardAggregatesBoundedEntries(t *testing.T) {
	logger := New(4)
	logger.Add(Entry{Client: "192.0.2.10", Domain: "example.com", Action: "forwarded", Upstream: "tls://one.example:853", Duration: 10})
	logger.Add(Entry{Client: "192.0.2.10", Domain: "blocked.example", Action: string(rules.ActionBlock), Duration: 2})
	logger.Add(Entry{Client: "192.0.2.11", Domain: "example.com", Action: "forwarded", Upstream: "tls://one.example:853", Duration: 30})
	logger.Add(Entry{Client: "192.0.2.12", Domain: "other.example", Action: "forwarded", Upstream: "tls://two.example:853", Duration: 50})
	logger.Add(Entry{Client: "192.0.2.12", Domain: "other.example", Action: "forwarded", Upstream: "tls://two.example:853", Duration: 70})

	dashboard := logger.Dashboard()
	if dashboard.AverageProcessingMS != 32 {
		t.Fatalf("average processing time = %d, want 32", dashboard.AverageProcessingMS)
	}
	if len(dashboard.ClientIPs) == 0 || dashboard.ClientIPs[0].Name != "192.0.2.12" || dashboard.ClientIPs[0].Count != 2 {
		t.Fatalf("unexpected client aggregation: %#v", dashboard.ClientIPs)
	}
	if len(dashboard.Domains) == 0 || dashboard.Domains[0].Name != "other.example" || dashboard.Domains[0].Count != 2 {
		t.Fatalf("unexpected domain aggregation: %#v", dashboard.Domains)
	}
	if len(dashboard.BlockedDomains) != 1 || dashboard.BlockedDomains[0].Name != "blocked.example" {
		t.Fatalf("unexpected blocked domain aggregation: %#v", dashboard.BlockedDomains)
	}
	if len(dashboard.Upstreams) != 2 || dashboard.Upstreams[0].Address != "tls://two.example:853" || dashboard.Upstreams[0].Count != 2 || dashboard.Upstreams[0].AverageDurationMS != 60 {
		t.Fatalf("unexpected upstream aggregation: %#v", dashboard.Upstreams)
	}
}
