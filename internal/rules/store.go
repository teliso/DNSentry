package rules

import (
	"runtime/debug"
	"slices"
	"sort"
	"strings"
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
// and a sorted index with one reference per domain, pointing at its rule.
type snapshot struct {
	lists []*ruleList
	index []ref
	total int
}

func NewStore(file string) *Store {
	store := &Store{file: file, remote: make(map[string]*ruleList)}
	store.snapshot.Store(&snapshot{})
	return store
}

// Match returns the rule that applies to domain: the rule for the most
// specific matching name, walking from domain up through its parents.
func (s *Store) Match(domain string) (Entry, bool) {
	domain = dnsname.Normalize(domain)
	snap := s.snapshot.Load()
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		position, found := slices.BinarySearchFunc(snap.index, candidate, func(r ref, name string) int {
			return strings.Compare(snap.lists[r.list].domain(int(r.index)), name)
		})
		if found {
			r := snap.index[position]
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
	s.setRemoteList(newRuleList(source, entries))
}

func (s *Store) setRemoteList(list *ruleList) {
	s.update(func() { s.remote[list.source] = list })
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

func (s *Store) setLocal(list *ruleList) {
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
	total := 0
	for _, list := range lists {
		total += list.len()
	}
	return &snapshot{lists: lists, index: buildIndex(lists), total: total}
}
