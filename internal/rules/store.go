package rules

import (
	"bufio"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/teliso/DNSentry/internal/dnsname"
)

type Action string

const (
	ActionBlock   Action = "block"
	ActionAllow   Action = "allow"
	ActionRewrite Action = "rewrite"
)

type Entry struct {
	Domain string `json:"domain"`
	Action Action `json:"action"`
	IP     string `json:"ip,omitempty"`
	Source string `json:"source,omitempty"`
}

type parsedRule struct {
	action Action
	ip     net.IP
}

type ruleSnapshot struct {
	rules   map[string]parsedRule
	entries []Entry
}

// Store keeps mutable source inputs separate from the immutable lookup
// snapshot used by DNS query workers. Rebuilds never block Match calls.
type Store struct {
	stateMu       sync.Mutex
	rebuildMu     sync.Mutex
	fileMu        sync.Mutex
	file          string
	snapshot      atomic.Pointer[ruleSnapshot]
	localEntries  []Entry
	remoteEntries map[string][]Entry
}

func NewStore(file string) *Store {
	store := &Store{file: file, remoteEntries: make(map[string][]Entry)}
	store.snapshot.Store(&ruleSnapshot{rules: make(map[string]parsedRule)})
	return store
}

func (s *Store) Reload() error {
	file, err := os.Open(s.file)
	if err != nil {
		return err
	}
	defer file.Close()

	entries := make([]Entry, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		entry, _, ok := parseRule(scanner.Text())
		if ok {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	s.replaceLocal(entries)
	return nil
}

func (s *Store) Match(domain string) (Action, net.IP, bool) {
	domain = dnsname.Normalize(domain)
	if domain == "" {
		return "", nil, false
	}
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return "", nil, false
	}
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		if rule, ok := snapshot.rules[candidate]; ok {
			return rule.action, rule.ip, true
		}
	}
	return "", nil, false
}

// Len returns the number of active rules without copying them.
func (s *Store) Len() int {
	if snapshot := s.snapshot.Load(); snapshot != nil {
		return len(snapshot.entries)
	}
	return 0
}

func (s *Store) List() []Entry {
	snapshot := s.snapshot.Load()
	if snapshot == nil || len(snapshot.entries) == 0 {
		return nil
	}
	result := make([]Entry, len(snapshot.entries))
	copy(result, snapshot.entries)
	return result
}

func (s *Store) Add(domain string, action Action) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	domain = dnsname.Normalize(domain)
	if !dnsname.Valid(domain) || (action != ActionBlock && action != ActionAllow) {
		return errors.New("invalid domain or action")
	}

	data, err := os.ReadFile(s.file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	prefix := "||"
	if action == ActionAllow {
		prefix = "@@||"
	}
	line := prefix + domain + "^\n"
	if !strings.Contains("\n"+string(data), "\n"+line) {
		data = append(data, []byte(line)...)
	}
	if err := os.WriteFile(s.file, data, 0644); err != nil {
		return err
	}
	return s.Reload()
}

func (s *Store) Delete(domain string, action Action) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	domain = dnsname.Normalize(domain)
	data, err := os.ReadFile(s.file)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		entry, _, ok := parseRule(line)
		if ok && entry.Domain == domain && entry.Action == action {
			continue
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(s.file, []byte(strings.Join(kept, "\n")), 0644); err != nil {
		return err
	}
	return s.Reload()
}

func (s *Store) replaceLocal(entries []Entry) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	s.localEntries = cloneEntries(entries)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *Store) replaceRemote(source string, entries []Entry) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	if s.remoteEntries == nil {
		s.remoteEntries = make(map[string][]Entry)
	}
	s.remoteEntries[source] = cloneEntries(entries)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *Store) removeRemote(source string) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	delete(s.remoteEntries, source)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *Store) copyInputsLocked() ([]Entry, map[string][]Entry) {
	local := cloneEntries(s.localEntries)
	remote := make(map[string][]Entry, len(s.remoteEntries))
	for source, entries := range s.remoteEntries {
		remote[source] = cloneEntries(entries)
	}
	return local, remote
}

func buildRuleSnapshot(localEntries []Entry, remoteEntries map[string][]Entry) *ruleSnapshot {
	entries := make([]Entry, 0, len(localEntries))
	selected := make(map[string]ruleCandidate)
	addRule := func(entry Entry, local bool) {
		candidate := ruleCandidate{rule: parsedRuleFromEntry(entry), local: local}
		if current, exists := selected[entry.Domain]; exists {
			candidate = preferRule(current, candidate)
		}
		selected[entry.Domain] = candidate
	}
	for _, entry := range localEntries {
		addRule(entry, true)
		entries = append(entries, entry)
	}
	remoteSources := make([]string, 0, len(remoteEntries))
	for source := range remoteEntries {
		remoteSources = append(remoteSources, source)
	}
	sort.Strings(remoteSources)
	for _, source := range remoteSources {
		for _, entry := range remoteEntries[source] {
			addRule(entry, false)
			entries = append(entries, entry)
		}
	}
	rules := make(map[string]parsedRule, len(selected))
	for domain, candidate := range selected {
		rules[domain] = candidate.rule
	}
	return &ruleSnapshot{rules: rules, entries: entries}
}

func cloneEntries(entries []Entry) []Entry {
	if len(entries) == 0 {
		return nil
	}
	cloned := make([]Entry, len(entries))
	copy(cloned, entries)
	return cloned
}

func parseRule(line string) (Entry, parsedRule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return Entry{}, parsedRule{}, false
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if ip := net.ParseIP(fields[0]); ip != nil {
			if isBlockingIP(ip) {
				for _, value := range fields[1:] {
					domain := dnsname.Normalize(value)
					if dnsname.Valid(domain) {
						return Entry{Domain: domain, Action: ActionBlock, IP: ip.String()}, parsedRule{action: ActionBlock, ip: ip}, true
					}
				}
			}
			return Entry{}, parsedRule{}, false
		}
	}

	action := ActionBlock
	if strings.HasPrefix(line, "@@") {
		action = ActionAllow
		line = strings.TrimPrefix(line, "@@")
	}
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	line = strings.TrimSuffix(line, "^")
	domain := dnsname.Normalize(line)
	if !dnsname.Valid(domain) {
		return Entry{}, parsedRule{}, false
	}
	return Entry{Domain: domain, Action: action}, parsedRule{action: action}, true
}

func isBlockingIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}
