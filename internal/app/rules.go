package app

import (
	"bufio"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type RuleAction string

const (
	ActionBlock   RuleAction = "block"
	ActionAllow   RuleAction = "allow"
	ActionRewrite RuleAction = "rewrite"
)

type RuleEntry struct {
	Domain string     `json:"domain"`
	Action RuleAction `json:"action"`
	IP     string     `json:"ip,omitempty"`
	Source string     `json:"source,omitempty"`
}

type parsedRule struct {
	action RuleAction
	ip     net.IP
}

type ruleSnapshot struct {
	rules   map[string]parsedRule
	entries []RuleEntry
}

// RuleStore keeps mutable source inputs separate from the immutable lookup
// snapshot used by DNS query workers. Rebuilds never block Match calls.
type RuleStore struct {
	stateMu       sync.Mutex
	rebuildMu     sync.Mutex
	fileMu        sync.Mutex
	file          string
	snapshot      atomic.Pointer[ruleSnapshot]
	localEntries  []RuleEntry
	remoteEntries map[string][]RuleEntry
}

func NewRuleStore(file string) *RuleStore {
	store := &RuleStore{file: file, remoteEntries: make(map[string][]RuleEntry)}
	store.snapshot.Store(&ruleSnapshot{rules: make(map[string]parsedRule)})
	return store
}

func (s *RuleStore) Reload() error {
	file, err := os.Open(s.file)
	if err != nil {
		return err
	}
	defer file.Close()

	entries := make([]RuleEntry, 0)
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

func (s *RuleStore) Match(domain string) (RuleAction, net.IP, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return "", nil, false
	}
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return "", nil, false
	}
	for candidate := domain; candidate != ""; candidate = parentDomain(candidate) {
		if rule, ok := snapshot.rules[candidate]; ok {
			return rule.action, rule.ip, true
		}
	}
	return "", nil, false
}

func (s *RuleStore) List() []RuleEntry {
	snapshot := s.snapshot.Load()
	if snapshot == nil || len(snapshot.entries) == 0 {
		return nil
	}
	result := make([]RuleEntry, len(snapshot.entries))
	copy(result, snapshot.entries)
	return result
}

func (s *RuleStore) Add(domain string, action RuleAction) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	domain = normalizeDomain(domain)
	if !validDomain(domain) || (action != ActionBlock && action != ActionAllow) {
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

func (s *RuleStore) Delete(domain string, action RuleAction) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	domain = normalizeDomain(domain)
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

func (s *RuleStore) replaceLocal(entries []RuleEntry) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	s.localEntries = cloneRuleEntries(entries)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *RuleStore) replaceRemote(source string, entries []RuleEntry) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	if s.remoteEntries == nil {
		s.remoteEntries = make(map[string][]RuleEntry)
	}
	s.remoteEntries[source] = cloneRuleEntries(entries)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *RuleStore) removeRemote(source string) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	delete(s.remoteEntries, source)
	local, remote := s.copyInputsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildRuleSnapshot(local, remote))
}

func (s *RuleStore) copyInputsLocked() ([]RuleEntry, map[string][]RuleEntry) {
	local := cloneRuleEntries(s.localEntries)
	remote := make(map[string][]RuleEntry, len(s.remoteEntries))
	for source, entries := range s.remoteEntries {
		remote[source] = cloneRuleEntries(entries)
	}
	return local, remote
}

func buildRuleSnapshot(localEntries []RuleEntry, remoteEntries map[string][]RuleEntry) *ruleSnapshot {
	entries := make([]RuleEntry, 0, len(localEntries))
	selected := make(map[string]ruleCandidate)
	addRule := func(entry RuleEntry, local bool) {
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

func cloneRuleEntries(entries []RuleEntry) []RuleEntry {
	if len(entries) == 0 {
		return nil
	}
	cloned := make([]RuleEntry, len(entries))
	copy(cloned, entries)
	return cloned
}

func parseRule(line string) (RuleEntry, parsedRule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return RuleEntry{}, parsedRule{}, false
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if ip := net.ParseIP(fields[0]); ip != nil {
			if isBlockingIP(ip) {
				for _, value := range fields[1:] {
					domain := normalizeDomain(value)
					if validDomain(domain) {
						return RuleEntry{Domain: domain, Action: ActionBlock, IP: ip.String()}, parsedRule{action: ActionBlock, ip: ip}, true
					}
				}
			}
			return RuleEntry{}, parsedRule{}, false
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
	domain := normalizeDomain(line)
	if !validDomain(domain) {
		return RuleEntry{}, parsedRule{}, false
	}
	return RuleEntry{Domain: domain, Action: action}, parsedRule{action: action}, true
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	return value
}

func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " /\\,;()[]{}") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func parentDomain(domain string) string {
	if index := strings.IndexByte(domain, '.'); index >= 0 {
		return domain[index+1:]
	}
	return ""
}

func isBlockingIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}
