package rules

import (
	"fmt"
	"testing"
)

func TestIndexPrecedenceAndDuplicates(t *testing.T) {
	store := NewStore("")
	store.setLocal(newRuleList("", []Entry{{Domain: "both.test", Action: ActionBlock}, {Domain: "localwins.test", Action: ActionBlock}}))
	store.SetRemote("https://a", []Entry{
		{Domain: "both.test", Action: ActionAllow},
		{Domain: "localwins.test", Action: ActionAllow},
		{Domain: "dup.test", Action: ActionBlock},
		{Domain: "dup.test", Action: ActionAllow},
		{Domain: "hosts.test", Action: ActionBlock, IP: "0.0.0.0"},
		{Domain: "plain.test", Action: ActionBlock},
	})
	store.SetRemote("https://b", []Entry{{Domain: "dup.test", Action: ActionBlock}, {Domain: "only-b.test", Action: ActionBlock}})
	cases := []struct {
		domain string
		action Action
		source string
		ip     string
	}{
		{"both.test", ActionBlock, "", ""},                  // local beats remote even when remote allows
		{"localwins.test", ActionBlock, "", ""},             // ditto
		{"dup.test", ActionAllow, "https://a", ""},          // allow beats block within remote lists
		{"hosts.test", ActionBlock, "https://a", "0.0.0.0"}, // IP kept
		{"plain.test", ActionBlock, "https://a", ""},        // no IP although the list has some
		{"sub.only-b.test", ActionBlock, "https://b", ""},   // parent match
		{"SUB.Only-B.test.", ActionBlock, "https://b", ""},  // normalized
	}
	for _, c := range cases {
		got, ok := store.Match(c.domain)
		if !ok || got.Action != c.action || got.Source != c.source || got.IP != c.ip {
			t.Errorf("Match(%q) = %+v, %v; want action %s source %q ip %q", c.domain, got, ok, c.action, c.source, c.ip)
		}
	}
	if _, ok := store.Match("unlisted.test"); ok {
		t.Error("unlisted domain matched")
	}
	if got := store.Len(); got != 10 {
		t.Errorf("Len = %d, want 10 (duplicates counted)", got)
	}
}

func TestEmptyStoreMatchesNothing(t *testing.T) {
	store := NewStore("")
	if _, ok := store.Match("example.com"); ok {
		t.Fatal("empty store matched")
	}
	store.SetRemote("https://a", nil)
	if _, ok := store.Match("example.com"); ok {
		t.Fatal("empty list matched")
	}
}

func TestLargeListLookups(t *testing.T) {
	entries := make([]Entry, 0, 50000)
	for i := 0; i < 50000; i++ {
		entries = append(entries, Entry{Domain: fmt.Sprintf("host%d.example.test", i), Action: ActionBlock})
	}
	store := NewStore("")
	store.SetRemote("https://big", entries)
	for _, i := range []int{0, 1, 24999, 49999} {
		if _, ok := store.Match(fmt.Sprintf("host%d.example.test", i)); !ok {
			t.Errorf("host%d not found", i)
		}
	}
	if _, ok := store.Match("host50000.example.test"); ok {
		t.Error("absent host matched")
	}
}

func BenchmarkMatch400k(b *testing.B) {
	entries := make([]Entry, 0, 400000)
	for i := 0; i < 400000; i++ {
		entries = append(entries, Entry{Domain: fmt.Sprintf("h%d.ads%d.example.test", i, i%997), Action: ActionBlock})
	}
	store := NewStore("")
	store.SetRemote("https://big", entries)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Match("www.h12345.ads12345.example.org")                               // miss, several parents
		store.Match(fmt.Sprintf("h%d.ads%d.example.test", i%400000, (i%400000)%997)) // hit
	}
}
