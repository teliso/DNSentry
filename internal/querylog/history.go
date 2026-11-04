package querylog

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Saved (JSONL) logs can be browsed one day at a time. A day is read and
// filtered while it is scanned; at most maxHistoryEntries of the newest matches
// are kept.
const maxHistoryEntries = 200_000

// ErrNoHistory means that logs are not being saved to disk.
var ErrNoHistory = errors.New("saving logs to disk is not enabled")

// ErrBadDate means a date that is not YYYY-MM-DD.
var ErrBadDate = errors.New("date must look like 2006-01-02")

var dayPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// HistoryDays lists the days that have a saved log, newest first. It is empty
// when saving to disk is off.
func (l *Logger) HistoryDays() []string {
	p := l.persistence
	if p == nil {
		return nil
	}
	directory, base := filepath.Dir(p.filePrefix), filepath.Base(p.filePrefix)+"-"
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	var days []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, base) || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, base), ".jsonl")
		if _, err := time.Parse("2006-01-02", day); err == nil {
			days = append(days, day)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	return days
}

// historyEntries scans one saved day and returns the entries matching filter,
// newest first, the actions seen on that day, and whether old matches were dropped.
func (l *Logger) historyEntries(day string, filter Filter) (entries []Entry, actions []string, truncated bool, err error) {
	p := l.persistence
	if p == nil {
		return nil, nil, false, ErrNoHistory
	}
	if !dayPattern.MatchString(day) {
		return nil, nil, false, ErrBadDate
	}
	when, err := time.ParseInLocation("2006-01-02", day, time.Local)
	if err != nil {
		return nil, nil, false, ErrBadDate
	}
	file, err := os.Open(filePath(p.filePrefix, when))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	defer file.Close()

	search := strings.ToLower(strings.TrimSpace(filter.Search))
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var entry Entry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue // a line that is still being written, or damaged
		}
		if !seen[entry.Action] {
			seen[entry.Action] = true
			actions = append(actions, entry.Action)
		}
		if (filter.Action != "" && entry.Action != filter.Action) || (search != "" && !strings.Contains(entry.Domain, search) && !strings.Contains(entry.Client, search)) {
			continue
		}
		entries = append(entries, entry)
		if len(entries) >= 2*maxHistoryEntries { // keep the newest maxHistoryEntries
			entries = append(entries[:0], entries[len(entries)-maxHistoryEntries:]...)
			truncated = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, false, err
	}
	if len(entries) > maxHistoryEntries {
		entries = entries[len(entries)-maxHistoryEntries:]
		truncated = true
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 { // the file is oldest first
		entries[i], entries[j] = entries[j], entries[i]
	}
	sort.Strings(actions)
	return entries, actions, truncated, nil
}

// QueryHistory returns one page of a saved day (newest first), like Query.
func (l *Logger) QueryHistory(day string, filter Filter) (Page, error) {
	entries, actions, truncated, err := l.historyEntries(day, filter)
	if err != nil {
		return Page{}, err
	}
	limit := filter.Limit
	if limit <= 0 || limit > maxPageSize {
		limit = 100
	}
	offset := max(filter.Offset, 0)
	page := Page{Total: len(entries), Items: []Entry{}, Actions: actions, Truncated: truncated}
	if page.Actions == nil {
		page.Actions = []string{}
	}
	if offset < len(entries) {
		page.Items = append(page.Items, entries[offset:min(offset+limit, len(entries))]...)
	}
	return page, nil
}

// ExportHistory returns every kept entry of a saved day matching filter, newest first.
func (l *Logger) ExportHistory(day string, filter Filter) ([]Entry, error) {
	entries, _, _, err := l.historyEntries(day, filter)
	return entries, err
}
