package rules

// ruleList is one list of rules (the local file or one remote source) stored
// compactly: parallel slices instead of one 64-byte Entry per rule. With
// hundreds of thousands of rules this is what keeps memory use low.
type ruleList struct {
	source  string   // "" for the local file, else the list URL
	domains []string // normalized; also the keys of the lookup map
	allow   []bool   // false: block
	ipIndex []uint16 // index into ips + 1, or 0; nil when no rule has an IP
	ips     []string // distinct hosts-file IPs (rare, and highly repetitive)
}

func newRuleList(source string, entries []Entry) *ruleList {
	list := &ruleList{source: source, domains: make([]string, len(entries)), allow: make([]bool, len(entries))}
	var seen map[string]uint16
	for i, entry := range entries {
		list.domains[i] = entry.Domain
		list.allow[i] = entry.Action == ActionAllow
		if entry.IP == "" {
			continue
		}
		if list.ipIndex == nil {
			list.ipIndex = make([]uint16, len(entries))
			seen = map[string]uint16{}
		}
		index, ok := seen[entry.IP]
		if !ok && len(list.ips) < 1<<16-2 {
			list.ips = append(list.ips, entry.IP)
			index = uint16(len(list.ips))
			seen[entry.IP] = index
		}
		list.ipIndex[i] = index // 0 (not recorded) in the unrealistic case of 65k distinct IPs
	}
	return list
}

func (l *ruleList) len() int {
	if l == nil {
		return 0
	}
	return len(l.domains)
}

func (l *ruleList) isLocal() bool { return l.source == "" }

func (l *ruleList) entry(i int) Entry {
	entry := Entry{Domain: l.domains[i], Action: ActionBlock, Source: l.source}
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
