package querylog

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/teliso/DNSentry/internal/fsutil"
)

// Long-range statistics are hourly counters (no domains, no clients) kept for
// statsRetention and saved to a small file, so the dashboard can show days and
// weeks and the numbers survive a restart.
const (
	statsRetention     = 90 * 24 * time.Hour
	statsFlushInterval = 30 * time.Second
)

type hourBucket struct{ queries, blocked uint64 }

// statsFile is the on-disk form: [hour start (unix), queries, blocked] triples.
type statsFile struct {
	Version int        `json:"version"`
	Hours   [][3]int64 `json:"hours"`
}

type statsPersistence struct {
	path string
	stop chan struct{}
	done chan struct{}
}

// recordHourLocked counts one query in its hour. l.mu must be held.
func (l *Logger) recordHourLocked(now time.Time, blocked bool) {
	hour := now.Truncate(time.Hour).Unix()
	bucket, exists := l.hours[hour]
	if !exists {
		cutoff := now.Add(-statsRetention).Unix()
		for stamp := range l.hours {
			if stamp < cutoff {
				delete(l.hours, stamp)
			}
		}
	}
	bucket.queries++
	if blocked {
		bucket.blocked++
	}
	l.hours[hour] = bucket
	l.hoursDirty = true
}

// History returns counters for window: "24h" gives 24 hourly points, "7d",
// "30d" and "90d" give one point per day (local time), oldest first.
func (l *Logger) History(window string) []MetricPoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	if window == "24h" {
		start := now.Truncate(time.Hour)
		points := make([]MetricPoint, 0, 24)
		for i := 23; i >= 0; i-- {
			at := start.Add(-time.Duration(i) * time.Hour)
			bucket := l.hours[at.Unix()]
			points = append(points, MetricPoint{Time: at.Format(time.RFC3339), Queries: bucket.queries, Blocked: bucket.blocked})
		}
		return points
	}
	days := map[string]int{"7d": 7, "30d": 30, "90d": 90}[window]
	if days == 0 {
		days = 7
	}
	year, month, day := now.Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	points := make([]MetricPoint, days)
	for i := range points {
		points[i].Time = today.AddDate(0, 0, i-days+1).Format(time.RFC3339)
	}
	first := today.AddDate(0, 0, 1-days)
	for stamp, bucket := range l.hours {
		at := time.Unix(stamp, 0).In(now.Location())
		if at.Before(first) {
			continue
		}
		y, m, d := at.Date()
		day := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
		index := int(day.Sub(first).Hours()/24 + 0.5) // rounding absorbs DST days of 23 or 25 hours
		if index >= 0 && index < days {
			points[index].Queries += bucket.queries
			points[index].Blocked += bucket.blocked
		}
	}
	return points
}

// EnableStats loads the saved counters from path and keeps saving them there
// until Close. A missing file is fine; an unreadable one is reported and replaced.
func (l *Logger) EnableStats(path string) error {
	var loadErr error
	if data, err := os.ReadFile(path); err == nil {
		var saved statsFile
		if err := json.Unmarshal(data, &saved); err != nil {
			loadErr = fmt.Errorf("ignoring unreadable statistics file: %w", err)
		} else {
			l.mu.Lock()
			cutoff := time.Now().Add(-statsRetention).Unix()
			for _, hour := range saved.Hours {
				if hour[0] >= cutoff {
					bucket := l.hours[hour[0]]
					bucket.queries += uint64(hour[1])
					bucket.blocked += uint64(hour[2])
					l.hours[hour[0]] = bucket
				}
			}
			l.mu.Unlock()
		}
	}
	l.statsSaver = &statsPersistence{path: path, stop: make(chan struct{}), done: make(chan struct{})}
	go l.runStatsSaver(l.statsSaver)
	return loadErr
}

func (l *Logger) runStatsSaver(p *statsPersistence) {
	defer close(p.done)
	ticker := time.NewTicker(statsFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.flushStats(p)
		case <-p.stop:
			l.flushStats(p)
			return
		}
	}
}

func (l *Logger) flushStats(p *statsPersistence) {
	l.mu.Lock()
	if !l.hoursDirty {
		l.mu.Unlock()
		return
	}
	saved := statsFile{Version: 1, Hours: make([][3]int64, 0, len(l.hours))}
	for stamp, bucket := range l.hours {
		saved.Hours = append(saved.Hours, [3]int64{stamp, int64(bucket.queries), int64(bucket.blocked)})
	}
	l.hoursDirty = false
	l.mu.Unlock()
	data, err := json.Marshal(saved)
	if err == nil {
		err = fsutil.WriteFileAtomic(p.path, data, 0600)
	}
	if err != nil {
		l.mu.Lock()
		l.hoursDirty = true // try again next time
		l.mu.Unlock()
		slog.Warn("could not save statistics", "path", p.path, "error", err)
	}
}

func (l *Logger) closeStats() {
	if l.statsSaver == nil {
		return
	}
	close(l.statsSaver.stop)
	<-l.statsSaver.done
	l.statsSaver = nil
}
