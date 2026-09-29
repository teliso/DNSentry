package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type QueryLogPersistenceConfig struct {
	Enabled       bool
	File          string
	RetentionDays int
}

type queryLogPersistence struct {
	filePrefix    string
	retentionDays int
	queue         chan QueryLogEntry
	stop          chan struct{}
	done          chan struct{}
	enqueueMu     sync.RWMutex
	closing       bool
	errMu         sync.Mutex
	err           error
}

const queryLogPersistenceQueueSize = 1024

func NewQueryLoggerWithPersistence(max int, config QueryLogPersistenceConfig) (*QueryLogger, error) {
	logger := newQueryLogger(max)
	if !config.Enabled {
		return logger, nil
	}
	config.File = strings.TrimSpace(config.File)
	if config.File == "" {
		config.File = filepath.Join("data", "querylog")
	}
	if config.RetentionDays == 0 {
		config.RetentionDays = 7
	}
	if config.RetentionDays < 1 || config.RetentionDays > 365 {
		return nil, fmt.Errorf("query log retention days must be between 1 and 365")
	}
	if err := os.MkdirAll(filepath.Dir(config.File), 0755); err != nil {
		return nil, fmt.Errorf("create query log directory: %w", err)
	}
	if err := cleanPersistedQueryLogs(config.File, config.RetentionDays, time.Now()); err != nil {
		return nil, fmt.Errorf("clean query logs: %w", err)
	}
	entries, err := loadPersistedQueryLogs(queryLogFilePath(config.File, time.Now()), logger.max)
	if err != nil {
		return nil, fmt.Errorf("load query logs: %w", err)
	}
	logger.entries = entries
	logger.persistence = &queryLogPersistence{
		filePrefix:    config.File,
		retentionDays: config.RetentionDays,
		queue:         make(chan QueryLogEntry, queryLogPersistenceQueueSize),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go logger.persistence.run()
	return logger, nil
}

func (l *QueryLogger) enqueuePersistence(entry QueryLogEntry) {
	persistence := l.persistence
	if persistence == nil {
		return
	}
	persistence.enqueueMu.RLock()
	defer persistence.enqueueMu.RUnlock()
	if persistence.closing {
		return
	}
	select {
	case persistence.queue <- entry:
	default:
		// Persistence is best effort: never delay a DNS query when disk logging falls behind.
	}
}

func (l *QueryLogger) Close() error {
	persistence := l.persistence
	if persistence == nil {
		return nil
	}
	persistence.enqueueMu.Lock()
	if !persistence.closing {
		persistence.closing = true
		close(persistence.stop)
	}
	persistence.enqueueMu.Unlock()
	<-persistence.done
	return persistence.error()
}

func (p *queryLogPersistence) run() {
	defer close(p.done)
	var file *os.File
	var writer *bufio.Writer
	currentDate := ""
	defer func() {
		p.closeFile(file, writer)
	}()
	for {
		select {
		case entry := <-p.queue:
			file, writer, currentDate = p.writeEntry(entry, file, writer, currentDate)
		case <-p.stop:
			for {
				select {
				case entry := <-p.queue:
					file, writer, currentDate = p.writeEntry(entry, file, writer, currentDate)
				default:
					return
				}
			}
		}
	}
}

func (p *queryLogPersistence) writeEntry(entry QueryLogEntry, file *os.File, writer *bufio.Writer, currentDate string) (*os.File, *bufio.Writer, string) {
	entryTime := time.Now()
	if parsed, err := time.Parse(time.RFC3339, entry.Time); err == nil {
		entryTime = parsed
	}
	date := entryTime.Format("2006-01-02")
	if date != currentDate {
		p.closeFile(file, writer)
		if err := cleanPersistedQueryLogs(p.filePrefix, p.retentionDays, entryTime); err != nil {
			p.setError(err)
		}
		opened, err := os.OpenFile(queryLogFilePath(p.filePrefix, entryTime), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			p.setError(err)
			return nil, nil, ""
		}
		file = opened
		writer = bufio.NewWriter(file)
		currentDate = date
	}
	if writer == nil {
		return file, writer, currentDate
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		p.setError(err)
		return file, writer, currentDate
	}
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		p.setError(err)
	}
	return file, writer, currentDate
}

func (p *queryLogPersistence) closeFile(file *os.File, writer *bufio.Writer) {
	if writer != nil {
		if err := writer.Flush(); err != nil {
			p.setError(err)
		}
	}
	if file != nil {
		if err := file.Close(); err != nil {
			p.setError(err)
		}
	}
}

func (p *queryLogPersistence) setError(err error) {
	if err == nil {
		return
	}
	p.errMu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.errMu.Unlock()
}

func (p *queryLogPersistence) error() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

func queryLogFilePath(prefix string, when time.Time) string {
	return prefix + "-" + when.Format("2006-01-02") + ".jsonl"
}

func loadPersistedQueryLogs(path string, max int) ([]QueryLogEntry, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	entries := make([]QueryLogEntry, 0, max)
	for scanner.Scan() {
		var entry QueryLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
		if len(entries) > max {
			entries = entries[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	return entries, nil
}

func cleanPersistedQueryLogs(prefix string, retentionDays int, now time.Time) error {
	directory := filepath.Dir(prefix)
	base := filepath.Base(prefix) + "-"
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	cutoff := startOfToday.AddDate(0, 0, -(retentionDays - 1))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), base) || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		date, err := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(entry.Name(), base), ".jsonl"))
		if err != nil || !date.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
