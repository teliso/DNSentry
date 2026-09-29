package rules

import (
	"errors"
	"os"
	"strings"

	"github.com/teliso/DNSentry/internal/dnsname"
	"github.com/teliso/DNSentry/internal/fsutil"
)

var (
	ErrInvalidRule = errors.New("invalid domain or action")
	ErrRuleExists  = errors.New("rule already exists")
	ErrRuleMissing = errors.New("rule not found in the local rules file")
)

// maxLocalFileBytes bounds the local rules file accepted through the API.
const maxLocalFileBytes = 16 << 20

// LocalSummary describes the result of parsing local rules text.
type LocalSummary struct {
	Rules int `json:"rules"`
	// IgnoredLines lists (1-based) lines that are neither blank, comments nor
	// supported rules, capped at maxIgnoredReported.
	IgnoredLines []int `json:"ignored_lines"`
	Ignored      int   `json:"ignored"`
}

const maxIgnoredReported = 50

func parseLocal(text string) ([]Entry, LocalSummary) {
	var entries []Entry
	summary := LocalSummary{IgnoredLines: []int{}}
	for index, line := range strings.Split(text, "\n") {
		parsed := ParseLine(line)
		if parsed == nil {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && trimmed[0] != '#' && trimmed[0] != '!' {
				summary.Ignored++
				if len(summary.IgnoredLines) < maxIgnoredReported {
					summary.IgnoredLines = append(summary.IgnoredLines, index+1)
				}
			}
			continue
		}
		entries = append(entries, parsed...)
	}
	summary.Rules = len(entries)
	return entries, summary
}

// Reload re-reads the local rules file. A missing file means no local rules.
func (s *Store) Reload() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	_, err := s.reloadLocked()
	return err
}

func (s *Store) reloadLocked() (string, error) {
	data, err := os.ReadFile(s.file)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	entries, _ := parseLocal(string(data))
	s.setLocal(entries)
	return string(data), nil
}

// LocalText returns the raw content of the local rules file.
func (s *Store) LocalText() (string, error) {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	data, err := os.ReadFile(s.file)
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(data), err
}

// SetLocalText replaces the local rules file with text, keeping comments and
// formatting as written, and activates the rules it contains.
func (s *Store) SetLocalText(text string) (LocalSummary, error) {
	if len(text) > maxLocalFileBytes {
		return LocalSummary{}, errors.New("rules file is too large")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	entries, summary := parseLocal(text)
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if err := fsutil.WriteFileAtomic(s.file, []byte(text), 0644); err != nil {
		return LocalSummary{}, err
	}
	s.setLocal(entries)
	return summary, nil
}

// normalizeRuleInput accepts a bare domain or a single rule in any supported
// syntax and returns the rule it denotes. An "@@" prefix forces allow.
func normalizeRuleInput(input string, action Action) (Entry, error) {
	input = strings.TrimSpace(input)
	if action != ActionBlock && action != ActionAllow {
		return Entry{}, ErrInvalidRule
	}
	parsed := ParseLine(input)
	if len(parsed) != 1 {
		return Entry{}, ErrInvalidRule
	}
	entry := parsed[0]
	if !strings.HasPrefix(input, "@@") {
		entry.Action = action
	}
	entry.IP = ""
	return entry, nil
}

// Add appends a rule for domain to the local rules file. domain may also be
// written as "||domain^" or "@@||domain^".
func (s *Store) Add(domain string, action Action) (Entry, error) {
	entry, err := normalizeRuleInput(domain, action)
	if err != nil {
		return Entry{}, err
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	text, err := s.reloadLocked()
	if err != nil {
		return Entry{}, err
	}
	s.stateMu.RLock()
	for _, existing := range s.local {
		if existing.Domain == entry.Domain && existing.Action == entry.Action {
			s.stateMu.RUnlock()
			return Entry{}, ErrRuleExists
		}
	}
	s.stateMu.RUnlock()
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += entry.Text() + "\n"
	if err := fsutil.WriteFileAtomic(s.file, []byte(text), 0644); err != nil {
		return Entry{}, err
	}
	_, err = s.reloadLocked()
	return entry, err
}

// Delete removes every local rule for exactly domain with the given action.
// A multi-domain hosts line only loses the matching name.
func (s *Store) Delete(domain string, action Action) error {
	domain = dnsname.Normalize(domain)
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	data, err := os.ReadFile(s.file)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrRuleMissing
		}
		return err
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	removed := false
	for _, line := range lines {
		entries := ParseLine(line)
		matched := false
		for _, entry := range entries {
			if entry.Domain == domain && entry.Action == action {
				matched = true
			}
		}
		if !matched {
			kept = append(kept, line)
			continue
		}
		removed = true
		if len(entries) > 1 { // hosts line: keep the other names
			fields := []string{entries[0].IP}
			for _, entry := range entries {
				if entry.Domain != domain {
					fields = append(fields, entry.Domain)
				}
			}
			kept = append(kept, strings.Join(fields, " "))
		}
	}
	if !removed {
		return ErrRuleMissing
	}
	if err := fsutil.WriteFileAtomic(s.file, []byte(strings.Join(kept, "\n")), 0644); err != nil {
		return err
	}
	_, err = s.reloadLocked()
	return err
}
