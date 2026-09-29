package rules

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/teliso/DNSentry/internal/dnsname"
)

// Store holds the local and remote rule lists and an immutable lookup snapshot
// built from them. Match only reads the snapshot, so rebuilding after an edit
// or list refresh never blocks DNS queries.
//
// Rule slices are treated as immutable once handed to the store: updates
// replace them wholesale, which lets readers use them without copying.
type Store struct {
	file   string
	fileMu sync.Mutex // serialises edits of the local rules file

	rebuildMu sync.Mutex // orders snapshot rebuilds so the newest inputs win
	stateMu   sync.RWMutex
	local     []Entry
	remote    map[string][]Entry

	snapshot atomic.Pointer[snapshot]
}

type snapshot struct {
	rules map[string]Entry // effective rule per domain
	total int
}

func NewStore(file string) *Store {
	store := &Store{file: file, remote: make(map[string][]Entry)}
	store.snapshot.Store(&snapshot{rules: map[string]Entry{}})
	return store
}

// Match returns the rule that applies to domain: the rule for the most
// specific matching name, walking from domain up through its parents.
func (s *Store) Match(domain string) (Entry, bool) {
	domain = dnsname.Normalize(domain)
	rules := s.snapshot.Load().rules
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		if rule, ok := rules[candidate]; ok {
			return rule, true
		}
	}
	return Entry{}, false
}

// Len returns the number of loaded rules, including duplicates across lists.
func (s *Store) Len() int {
	return s.snapshot.Load().total
}

// SetRemote replaces the rules loaded from source. The store takes ownership
// of entries.
func (s *Store) SetRemote(source string, entries []Entry) {
	s.update(func() { s.remote[source] = entries })
}

// RemoveRemote unloads the rules of source.
func (s *Store) RemoveRemote(source string) {
	s.update(func() { delete(s.remote, source) })
}

// HasRemote reports whether rules from source are loaded.
func (s *Store) HasRemote(source string) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	_, ok := s.remote[source]
	return ok
}

func (s *Store) setLocal(entries []Entry) {
	s.update(func() { s.local = entries })
}

func (s *Store) update(mutate func()) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	mutate()
	lists := s.listsLocked()
	s.stateMu.Unlock()
	s.snapshot.Store(buildSnapshot(lists))
}

// lists returns every rule list in precedence order: local rules first, then
// remote sources ordered by URL.
func (s *Store) lists() [][]Entry {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.listsLocked()
}

func (s *Store) listsLocked() [][]Entry {
	sources := make([]string, 0, len(s.remote))
	for source := range s.remote {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	lists := make([][]Entry, 0, len(sources)+1)
	lists = append(lists, s.local)
	for _, source := range sources {
		lists = append(lists, s.remote[source])
	}
	return lists
}

func buildSnapshot(lists [][]Entry) *snapshot {
	size := 0
	for _, list := range lists {
		size += len(list)
	}
	rules := make(map[string]Entry, size)
	for _, list := range lists {
		for _, entry := range list {
			if current, exists := rules[entry.Domain]; !exists || wins(entry, current) {
				rules[entry.Domain] = entry
			}
		}
	}
	return &snapshot{rules: rules, total: size}
}

// wins reports whether next overrides current for the same domain. Local rules
// override remote ones; within the same kind an allow rule overrides a block.
func wins(next, current Entry) bool {
	nextLocal, currentLocal := next.Source == "", current.Source == ""
	if nextLocal != currentLocal {
		return nextLocal
	}
	return next.Action == ActionAllow && current.Action != ActionAllow
}
