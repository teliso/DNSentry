package querylog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sum(points []MetricPoint) (queries, blocked uint64) {
	for _, p := range points {
		queries += p.Queries
		blocked += p.Blocked
	}
	return
}

func TestHistoryCountsHoursAndDays(t *testing.T) {
	logger := New(10)
	now := time.Now()
	logger.mu.Lock()
	logger.recordHourLocked(now, false)
	logger.recordHourLocked(now, true)
	logger.recordHourLocked(now.Add(-3*time.Hour), false)
	logger.recordHourLocked(now.AddDate(0, 0, -2), true)
	logger.recordHourLocked(now.AddDate(0, 0, -40), true) // outside 30 days
	logger.mu.Unlock()

	hourly := logger.History("24h")
	if len(hourly) != 24 {
		t.Fatalf("24h points = %d", len(hourly))
	}
	if q, b := sum(hourly); q < 3 || b < 1 { // the -3h entry may fall in the previous day but stays inside 24h
		t.Fatalf("24h totals = %d/%d", q, b)
	}
	if last := hourly[23]; last.Queries != 2 || last.Blocked != 1 {
		t.Fatalf("current hour = %#v", last)
	}
	week := logger.History("7d")
	if len(week) != 7 {
		t.Fatalf("7d points = %d", len(week))
	}
	if q, _ := sum(week); q != 4 {
		t.Fatalf("7d queries = %d, want 4", q)
	}
	month := logger.History("30d")
	if len(month) != 30 {
		t.Fatalf("30d points = %d", len(month))
	}
	if q, b := sum(month); q != 4 || b != 2 {
		t.Fatalf("30d totals = %d/%d, want 4/2", q, b)
	}
	if q, _ := sum(logger.History("90d")); q != 5 {
		t.Fatalf("90d queries = %d, want 5", q)
	}
}

func TestStatsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	first := New(10)
	if err := first.EnableStats(path); err != nil {
		t.Fatal(err)
	}
	first.Add(Entry{Domain: "a.test", Action: "forwarded"})
	first.Add(Entry{Domain: "b.test", Action: "block"})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("stats file: %v %v", info, err)
	}

	second := New(10)
	if err := second.EnableStats(path); err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if q, b := sum(second.History("24h")); q != 2 || b != 1 {
		t.Fatalf("restored totals = %d/%d, want 2/1", q, b)
	}

	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	third := New(10)
	if err := third.EnableStats(path); err == nil {
		t.Fatal("a corrupt statistics file went unreported")
	}
	third.Close()
}
