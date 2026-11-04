package rules

import (
	"bytes"
	"slices"
)

// ruleList is one list of rules (the local file or one remote source) stored
// compactly: all domains in one byte slice with an offset table, instead of a
// string and a 64-byte Entry per rule. With hundreds of thousands of rules
// this is what keeps memory use low. A list is immutable once built.
type ruleList struct {
	source  string   // "" for the local file, else the list URL
	blob    []byte   // the domains, concatenated
	offsets []uint32 // domain i is blob[offsets[i]:offsets[i+1]]
	allow   []bool   // false: block
	ipIndex []uint16 // index into ips + 1, or 0; nil when no rule has an IP
	ips     []string // distinct hosts-file IPs (rare, and highly repetitive)
}

// listBuilder collects rules one by one, so a big list never has to exist as
// a slice of Entry values.
type listBuilder struct {
	source  string
	blob    []byte
	offsets []uint32
	allow   []bool
	ipIndex []uint16
	ips     []string
	seenIP  map[string]uint16
}

func newListBuilder(source string) *listBuilder {
	return &listBuilder{source: source, offsets: []uint32{0}}
}

func (b *listBuilder) Add(entry Entry) {
	b.blob = append(b.blob, entry.Domain...)
	b.offsets = append(b.offsets, uint32(len(b.blob)))
	b.allow = append(b.allow, entry.Action == ActionAllow)
	n := len(b.allow)
	if entry.IP == "" {
		if b.ipIndex != nil {
			b.ipIndex = append(b.ipIndex, 0)
		}
		return
	}
	if b.ipIndex == nil {
		b.ipIndex = make([]uint16, n-1, cap(b.allow))
		b.seenIP = map[string]uint16{}
	}
	index, ok := b.seenIP[entry.IP]
	if !ok && len(b.ips) < 1<<16-2 {
		b.ips = append(b.ips, entry.IP)
		index = uint16(len(b.ips))
		b.seenIP[entry.IP] = index
	}
	b.ipIndex = append(b.ipIndex, index) // 0 (not recorded) in the unrealistic case of 65k distinct IPs
}

// Build returns the finished list, with no spare capacity.
func (b *listBuilder) Build() *ruleList {
	return &ruleList{
		source:  b.source,
		blob:    bytes.Clone(b.blob),
		offsets: slices.Clone(b.offsets),
		allow:   slices.Clone(b.allow),
		ipIndex: slices.Clone(b.ipIndex),
		ips:     slices.Clone(b.ips),
	}
}

func newRuleList(source string, entries []Entry) *ruleList {
	builder := newListBuilder(source)
	for _, entry := range entries {
		builder.Add(entry)
	}
	return builder.Build()
}

func (l *ruleList) len() int {
	if l == nil {
		return 0
	}
	return len(l.allow)
}

func (l *ruleList) isLocal() bool { return l.source == "" }

// domain returns rule i's domain as a view into the list's storage (it must
// not be modified; lists are never changed after they are built).
func (l *ruleList) domain(i int) []byte {
	return l.blob[l.offsets[i]:l.offsets[i+1]:l.offsets[i+1]]
}

func (l *ruleList) entry(i int) Entry {
	entry := Entry{Domain: string(l.domain(i)), Action: ActionBlock, Source: l.source}
	if l.allow[i] {
		entry.Action = ActionAllow
	}
	if l.ipIndex != nil && l.ipIndex[i] != 0 {
		entry.IP = l.ips[l.ipIndex[i]-1]
	}
	return entry
}

// ref locates a rule: which list, and where in it.
type ref struct {
	list  uint16
	index uint32
}

// buildIndex returns, sorted by domain, one reference per distinct domain: the
// rule that applies to it. Local rules override remote ones; within the same
// kind an allow rule overrides a block.
func buildIndex(lists []*ruleList) []ref {
	size := 0
	for _, list := range lists {
		size += list.len()
	}
	refs := make([]ref, 0, size)
	for li, list := range lists {
		for i := 0; i < list.len(); i++ {
			refs = append(refs, ref{list: uint16(li), index: uint32(i)})
		}
	}
	slices.SortFunc(refs, func(a, b ref) int {
		if c := bytes.Compare(lists[a.list].domain(int(a.index)), lists[b.list].domain(int(b.index))); c != 0 {
			return c
		}
		return precedence(lists, a, b)
	})
	// The first of each run of equal domains has the highest precedence.
	kept := refs[:0]
	for i, r := range refs {
		if i > 0 && bytes.Equal(lists[r.list].domain(int(r.index)), lists[kept[len(kept)-1].list].domain(int(kept[len(kept)-1].index))) {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) < len(refs)*9/10 {
		return slices.Clone(kept)
	}
	return kept
}

// precedence orders two rules for the same domain: negative when a wins.
func precedence(lists []*ruleList, a, b ref) int {
	la, lb := lists[a.list], lists[b.list]
	switch {
	case la.isLocal() != lb.isLocal():
		if la.isLocal() {
			return -1
		}
		return 1
	case la.allow[a.index] != lb.allow[b.index]:
		if la.allow[a.index] {
			return -1
		}
		return 1
	case a.list != b.list:
		return int(a.list) - int(b.list)
	}
	return int(a.index) - int(b.index)
}
