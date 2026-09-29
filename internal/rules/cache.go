package rules

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/teliso/DNSentry/internal/fsutil"
)

// sourceCache keeps the last successfully downloaded copy of every remote list
// on disk, so rules are active immediately after a restart and survive an
// unreachable source. Each source has a "<key>.rules" file with one canonical
// rule per line and a "<key>.json" file with its state.
type sourceCache struct {
	dir string // empty disables the cache
}

type cacheState struct {
	URL          string `json:"url"`
	LastUpdated  string `json:"last_updated,omitempty"`
	LastChecked  string `json:"last_checked,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:12])
}

func (c sourceCache) paths(url string) (rules, state string) {
	base := filepath.Join(c.dir, cacheKey(url))
	return base + ".rules", base + ".json"
}

// loadState returns the saved state of url, if any.
func (c sourceCache) loadState(url string) (cacheState, bool) {
	if c.dir == "" {
		return cacheState{}, false
	}
	_, statePath := c.paths(url)
	data, err := os.ReadFile(statePath)
	if err != nil {
		return cacheState{}, false
	}
	var state cacheState
	if json.Unmarshal(data, &state) != nil || state.URL != url {
		return cacheState{}, false
	}
	return state, true
}

// loadRules returns the cached rules of url.
func (c sourceCache) loadRules(url string) ([]Entry, error) {
	if c.dir == "" {
		return nil, os.ErrNotExist
	}
	rulesPath, _ := c.paths(url)
	file, err := os.Open(rulesPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var entries []Entry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		for _, entry := range ParseLine(scanner.Text()) {
			entry.Source = url
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

func (c sourceCache) saveRules(url string, entries []Entry) error {
	if c.dir == "" {
		return nil
	}
	var builder strings.Builder
	for _, entry := range entries {
		builder.WriteString(entry.Text())
		builder.WriteByte('\n')
	}
	rulesPath, _ := c.paths(url)
	return fsutil.WriteFileAtomic(rulesPath, []byte(builder.String()), 0644)
}

func (c sourceCache) saveState(state cacheState) error {
	if c.dir == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	_, statePath := c.paths(state.URL)
	return fsutil.WriteFileAtomic(statePath, data, 0644)
}

func (c sourceCache) remove(url string) {
	if c.dir == "" {
		return
	}
	rulesPath, statePath := c.paths(url)
	_ = os.Remove(rulesPath)
	_ = os.Remove(statePath)
}

// prune deletes cached lists that no configured source refers to.
func (c sourceCache) prune(urls []string) {
	if c.dir == "" {
		return
	}
	keep := make(map[string]bool, len(urls))
	for _, url := range urls {
		keep[cacheKey(url)] = true
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		key, _, found := strings.Cut(name, ".")
		if entry.IsDir() || !found || keep[key] || len(key) != 24 {
			continue
		}
		_ = os.Remove(filepath.Join(c.dir, name))
	}
}
