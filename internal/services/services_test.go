package services

import (
	"testing"

	"github.com/teliso/DNSentry/internal/dnsname"
)

func TestCatalogIsWellFormed(t *testing.T) {
	ids := map[string]bool{}
	owner := map[string]string{}
	for _, service := range Catalog {
		if service.ID == "" || service.Name == "" || service.Group == "" || len(service.Domains) == 0 || ids[service.ID] {
			t.Errorf("bad catalogue entry %+v", service)
		}
		ids[service.ID] = true
		for _, domain := range service.Domains {
			if dnsname.Normalize(domain) != domain || !dnsname.Valid(domain) {
				t.Errorf("%s: %q is not a canonical domain", service.ID, domain)
			}
			if other, taken := owner[domain]; taken {
				t.Errorf("%q belongs to both %s and %s", domain, other, service.ID)
			}
			owner[domain] = service.ID
		}
	}
}

func TestMatcherMatchesSubdomainsOfSelectedServicesOnly(t *testing.T) {
	matcher := NewMatcher([]string{"tiktok", "no-such-service"})
	for domain, want := range map[string]bool{
		"tiktok.com":           true,
		"www.tiktok.com":       true,
		"v16m.tiktokcdn.com":   true,
		"nottiktok.com":        false, // a different domain that merely ends the same way
		"tiktok.com.evil.test": false,
		"youtube.com":          false, // service not selected
		"com":                  false,
	} {
		if _, got := matcher.Match(domain); got != want {
			t.Errorf("Match(%q) = %v, want %v", domain, got, want)
		}
	}
	var none *Matcher
	if _, ok := none.Match("tiktok.com"); ok {
		t.Error("a nil matcher matched")
	}
}

func TestNormalizeKeepsCatalogueOrderAndReportsUnknown(t *testing.T) {
	known, unknown := Normalize([]string{"youtube", "tiktok", "youtube", "bogus", ""})
	if len(known) != 2 || known[0] != "tiktok" || known[1] != "youtube" || len(unknown) != 1 || unknown[0] != "bogus" {
		t.Fatalf("known=%v unknown=%v", known, unknown)
	}
}
