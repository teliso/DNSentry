package applog

import (
	"io"
	"log/slog"
	"testing"
)

func TestLevelsSearchAndOff(t *testing.T) {
	l := New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), slog.LevelInfo)
	logger := slog.New(l.Handler())
	logger.Debug("hidden")
	logger.Info("started", "port", 53)
	logger.Error("boom", "error", "disk full")
	if got := l.Entries(slog.LevelDebug, "", 0); len(got) != 2 || got[0].Message != "boom" {
		t.Fatalf("entries = %+v", got)
	}
	if got := l.Entries(slog.LevelError, "", 0); len(got) != 1 {
		t.Fatalf("level filter = %+v", got)
	}
	if got := l.Entries(slog.LevelDebug, "PORT=53", 0); len(got) != 1 || got[0].Message != "started" {
		t.Fatalf("search = %+v", got)
	}
	l.SetLevel(Off)
	logger.Error("silent")
	if l.Level() != "off" || len(l.Entries(slog.LevelDebug, "", 0)) != 2 {
		t.Fatal("off should record nothing")
	}
	l.Clear()
	if len(l.Entries(slog.LevelDebug, "", 0)) != 0 {
		t.Fatal("clear")
	}
}
