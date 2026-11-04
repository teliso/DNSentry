package rules

import (
	"runtime/debug"
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
	local     *ruleList
	remote    map[string]*ruleList

	snapshot atomic.Pointer[snapshot]
}

// snapshot is the immutable lookup structure: the lists in precedence order
// and, per domain, a reference to the rule that applies.
type snapshot struct {
	lists []*ruleList
	rules map[string]ref
	total int
}

func NewStore(file string) *Store {
	store := &Store{file: file, remote: make(map[string]*ruleList)}
	store.snapshot.Store(&snapshot{rules: map[string]ref{}})
	return store
}

// Match returns the rule that applies to domain: the rule for the most
// specific matching name, walking from domain up through its parents.
func (s *Store) Match(domain string) (Entry, bool) {
	domain = dnsname.Normalize(domain)
	snap := s.snapshot.Load()
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		if r, ok := snap.rules[candidate]; ok {
			return snap.lists[r.list].entry(int(r.index)), true
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
	list := newRuleList(source, entries)
	s.update(func() { s.remote[source] = list })
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
	list := newRuleList("", entries)
	s.update(func() { s.local = list })
}

func (s *Store) update(mutate func()) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	s.stateMu.Lock()
	mutate()
	lists := s.listsLocked()
	s.stateMu.Unlock()
	built := buildSnapshot(lists)
	s.snapshot.Store(built)
	if built.total >= releaseThreshold {
		// Parsing a big list leaves a lot of garbage; hand it back to the system now.
		debug.FreeOSMemory()
	}
}

// releaseThreshold is the rule count from which a rebuild is followed by
// returning freed memory to the operating system.
const releaseThreshold = 50_000

// lists returns every rule list in precedence order: local rules first, then
// remote sources ordered by URL.
func (s *Store) lists() []*ruleList {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.listsLocked()
}

func (s *Store) listsLocked() []*ruleList {
	sources := make([]string, 0, len(s.remote))
	for source := range s.remote {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	lists := make([]*ruleList, 0, len(sources)+1)
	if s.local != nil {
		lists = append(lists, s.local)
	}
	for _, source := range sources {
		lists = append(lists, s.remote[source])
	}
	return lists
}

func buildSnapshot(lists []*ruleList) *snapshot {
	size := 0
	for _, list := range lists {
		size += list.len()
	}
	rules := make(map[string]ref, size)
	for li, list := range lists {
		for i, domain := range list.domains {
			next := ref{list: uint16(li), index: uint32(i)}
			if current, exists := rules[domain]; !exists || wins(lists, next, current) {
				rules[domain] = next
			}
		}
	}
	return &snapshot{lists: lists, rules: rules, total: size}
}

// wins reports whether next overrides current for the same domain. Local rules
// override remote ones; within the same kind an allow rule overrides a block.
func wins(lists []*ruleList, next, current ref) bool {
	nextList, currentList := lists[next.list], lists[current.list]
	if nextList.isLocal() != currentList.isLocal() {
		return nextList.isLocal()
	}
	return nextList.allow[next.index] && !currentList.allow[current.index]
}
