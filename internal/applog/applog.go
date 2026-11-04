// Package applog keeps the program's own log (what it writes through slog) in a
// small in-memory ring so the console can show it, and lets the level be
// changed — or the log turned off — while the program runs.
package applog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Off silences the program log completely.
const Off = slog.Level(1000)

const capacity = 1000

// Entry is one line of the program log.
type Entry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Attrs   string `json:"attrs,omitempty"`
}

// Log is the slog handler plus the ring it feeds.
type Log struct {
	level slog.LevelVar
	inner slog.Handler

	mu    sync.Mutex
	ring  []Entry
	next  int
	count int
}

// New returns a Log that forwards to inner (usually the stderr handler) at the
// given level. inner must accept every level; filtering is done here.
func New(inner slog.Handler, level slog.Level) *Log {
	l := &Log{inner: inner, ring: make([]Entry, capacity)}
	l.level.Set(level)
	return l
}

// ParseLevel understands debug, info, warn, error and off.
func ParseLevel(text string) (slog.Level, error) {
	if strings.EqualFold(strings.TrimSpace(text), "off") {
		return Off, nil
	}
	var level slog.Level
	err := level.UnmarshalText([]byte(strings.TrimSpace(text)))
	return level, err
}

// SetLevel changes the level at run time.
func (l *Log) SetLevel(level slog.Level) { l.level.Set(level) }

// Level reports the current level as text ("off" when silenced).
func (l *Log) Level() string {
	if l.level.Level() >= Off {
		return "off"
	}
	return strings.ToLower(l.level.Level().String())
}

// Entries returns the retained lines, newest first, at least minLevel and
// containing search (case-insensitive) when it is not empty.
func (l *Log) Entries(minLevel slog.Level, search string, limit int) []Entry {
	search = strings.ToLower(search)
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Entry
	for i := 0; i < l.count && (limit <= 0 || len(out) < limit); i++ {
		entry := l.ring[(l.next-1-i+len(l.ring)*2)%len(l.ring)]
		var level slog.Level
		_ = level.UnmarshalText([]byte(entry.Level))
		if level < minLevel {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(entry.Message+" "+entry.Attrs), search) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// Clear forgets the retained lines.
func (l *Log) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next, l.count = 0, 0
	for i := range l.ring {
		l.ring[i] = Entry{}
	}
}

// Handler returns the slog.Handler to install with slog.SetDefault.
func (l *Log) Handler() slog.Handler { return &handler{log: l, inner: l.inner} }

type handler struct {
	log    *Log
	inner  slog.Handler
	attrs  []slog.Attr
	groups []string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.log.level.Level()
}

func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	var attrs []string
	add := func(attr slog.Attr) bool {
		key := strings.Join(append(append([]string(nil), h.groups...), attr.Key), ".")
		attrs = append(attrs, fmt.Sprintf("%s=%v", key, attr.Value))
		return true
	}
	for _, attr := range h.attrs {
		add(attr)
	}
	record.Attrs(add)
	var level string
	switch {
	case record.Level >= slog.LevelError:
		level = "error"
	case record.Level >= slog.LevelWarn:
		level = "warn"
	case record.Level >= slog.LevelInfo:
		level = "info"
	default:
		level = "debug"
	}
	when := record.Time
	if when.IsZero() {
		when = time.Now()
	}
	h.log.mu.Lock()
	h.log.ring[h.log.next] = Entry{Time: when.Format(time.RFC3339), Level: level, Message: record.Message, Attrs: strings.Join(attrs, " ")}
	h.log.next = (h.log.next + 1) % len(h.log.ring)
	if h.log.count < len(h.log.ring) {
		h.log.count++
	}
	h.log.mu.Unlock()
	return h.inner.Handle(ctx, record)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	clone.inner = h.inner.WithAttrs(attrs)
	return &clone
}

func (h *handler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.groups = append(append([]string(nil), h.groups...), name)
	clone.inner = h.inner.WithGroup(name)
	return &clone
}
