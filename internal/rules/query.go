package rules

import (
	"strings"

	"github.com/teliso/DNSentry/internal/dnsname"
)

// SourceLocal selects the local rules file in Filter.Source.
const SourceLocal = "local"

// Filter selects rules for Query.
type Filter struct {
	Search string // case-insensitive substring of the domain
	Action Action // empty for any
	Source string // "", SourceLocal or a remote source URL
	Offset int
	Limit  int
}

// Page is one page of matching rules.
type Page struct {
	Total int     `json:"total"`
	Items []Entry `json:"items"`
}

const maxPageSize = 500

// Query returns the rules that pass filter, local rules first.
func (s *Store) Query(filter Filter) Page {
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	limit := filter.Limit
	if limit <= 0 || limit > maxPageSize {
		limit = 100
	}
	offset := max(filter.Offset, 0)
	page := Page{Items: []Entry{}}
	for _, list := range s.lists() {
		if len(list) == 0 {
			continue
		}
		switch source := list[0].Source; {
		case filter.Source == SourceLocal && source != "":
			continue
		case filter.Source != "" && filter.Source != SourceLocal && source != filter.Source:
			continue
		}
		for _, entry := range list {
			if filter.Action != "" && entry.Action != filter.Action {
				continue
			}
			if search != "" && !strings.Contains(entry.Domain, search) {
				continue
			}
			if page.Total >= offset && len(page.Items) < limit {
				page.Items = append(page.Items, entry)
			}
			page.Total++
		}
	}
	return page
}

// Check explains how domain is filtered.
type Check struct {
	Domain string `json:"domain"`
	// Rule is the rule that decides the query, if any.
	Rule *Entry `json:"rule,omitempty"`
	// Candidates are all loaded rules for domain or one of its parents, in
	// precedence order of the lists they come from.
	Candidates []Entry `json:"candidates"`
}

const maxCheckCandidates = 100

// Check returns the effective rule for domain and every rule that could apply.
func (s *Store) Check(domain string) (Check, error) {
	domain = dnsname.Normalize(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(domain), "||"), "^"))
	if !dnsname.Valid(domain) {
		return Check{}, ErrInvalidRule
	}
	result := Check{Domain: domain, Candidates: []Entry{}}
	if rule, ok := s.Match(domain); ok {
		result.Rule = &rule
	}
	names := map[string]bool{}
	for name := domain; name != ""; name = dnsname.Parent(name) {
		names[name] = true
	}
	for _, list := range s.lists() {
		for _, entry := range list {
			if names[entry.Domain] && len(result.Candidates) < maxCheckCandidates {
				result.Candidates = append(result.Candidates, entry)
			}
		}
	}
	return result, nil
}

// Counts returns the number of rules per list: SourceLocal and each loaded
// remote source URL.
func (s *Store) Counts() map[string]int {
	counts := map[string]int{}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	counts[SourceLocal] = len(s.local)
	for source, entries := range s.remote {
		counts[source] = len(entries)
	}
	return counts
}
