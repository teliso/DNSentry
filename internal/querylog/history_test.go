package querylog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSavedLogsCanBeBrowsedByDay(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "querylog")
	logger, err := NewWithPersistence(10, PersistenceConfig{Enabled: true, File: prefix, RetentionDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		logger.Add(Entry{Domain: string(rune('a'+i)) + ".test", Client: "192.0.2.1", Action: "forwarded"})
	}
	logger.Add(Entry{Domain: "ads.test", Client: "192.0.2.2", Action: "block"})
	if err := logger.Close(); err != nil { // flushes the queue
		t.Fatal(err)
	}

	// A day from the past, written by hand.
	old := time.Now().AddDate(0, 0, -2)
	if err := os.WriteFile(filePath(prefix, old), []byte(`{"time":"x","domain":"old.test","type":"A","action":"cached"}`+"\n"+"not json\n"), 0600); err != nil {
		t.Fatal(err)
	}

	again, err := NewWithPersistence(10, PersistenceConfig{Enabled: true, File: prefix, RetentionDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	today := time.Now().Format("2006-01-02")
	days := again.HistoryDays()
	if len(days) != 2 || days[0] != today || days[1] != old.Format("2006-01-02") {
		t.Fatalf("days = %v", days)
	}

	page, err := again.QueryHistory(today, Filter{Limit: 4})
	if err != nil || page.Total != 6 || len(page.Items) != 4 || page.Items[0].Domain != "ads.test" || page.Items[3].Domain != "c.test" {
		t.Fatalf("page = %#v %v", page, err)
	}
	if len(page.Actions) != 2 || page.Actions[0] != "block" {
		t.Fatalf("actions = %v", page.Actions)
	}
	second, _ := again.QueryHistory(today, Filter{Limit: 4, Offset: 4})
	if len(second.Items) != 2 || second.Items[1].Domain != "a.test" {
		t.Fatalf("second page = %#v", second)
	}
	if filtered, _ := again.QueryHistory(today, Filter{Action: "block"}); filtered.Total != 1 {
		t.Fatalf("action filter: %#v", filtered)
	}
	if filtered, _ := again.QueryHistory(today, Filter{Search: "192.0.2.2"}); filtered.Total != 1 || filtered.Items[0].Domain != "ads.test" {
		t.Fatalf("search filter: %#v", filtered)
	}
	oldPage, err := again.QueryHistory(old.Format("2006-01-02"), Filter{})
	if err != nil || oldPage.Total != 1 || oldPage.Items[0].Domain != "old.test" {
		t.Fatalf("old day (a damaged line is skipped): %#v %v", oldPage, err)
	}
	if empty, err := again.QueryHistory("2001-01-01", Filter{}); err != nil || empty.Total != 0 || empty.Items == nil {
		t.Fatalf("a day without a file: %#v %v", empty, err)
	}
	for _, bad := range []string{"../../etc/passwd", "2026-1-1", "today", "2026-13-40"} {
		if _, err := again.QueryHistory(bad, Filter{}); err != ErrBadDate {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if entries, err := again.ExportHistory(today, Filter{}); err != nil || len(entries) != 6 {
		t.Fatalf("export: %d %v", len(entries), err)
	}

	memory := New(5)
	if _, err := memory.QueryHistory(today, Filter{}); err != ErrNoHistory || memory.HistoryDays() != nil {
		t.Fatalf("a logger without persistence: %v", err)
	}
}
