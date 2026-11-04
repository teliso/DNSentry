package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"
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
	hits := make([]string, 0, 1024)
	for i := 0; i < 400000; i++ {
		entries = append(entries, Entry{Domain: fmt.Sprintf("h%d.ads%d.example.test", i, i%997), Action: ActionBlock})
		if i%400 == 0 {
			hits = append(hits, entries[i].Domain)
		}
	}
	store := NewStore("")
	start := time.Now()
	store.SetRemote("https://big", entries)
	b.Logf("building the lookup structure for 400k rules: %v", time.Since(start))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Match("www.h12345.ads12345.example.org") // miss, several parents
		store.Match(hits[i%len(hits)])                 // hit
	}
}

func TestParseLocalReaderMatchesLineSemantics(t *testing.T) {
	long := strings.Repeat("x", 200000) // a line far longer than the read buffer
	text := "||a.test^\n# comment\n" + long + " junk\n@@b.test\r\n0.0.0.0 c.test d.test\nlast.test"
	list, summary, err := parseLocalReader(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if list.len() != 5 || summary.Rules != 5 || summary.Ignored != 1 || len(summary.IgnoredLines) != 1 || summary.IgnoredLines[0] != 3 {
		t.Fatalf("list %d rules, summary %+v", list.len(), summary)
	}
	if got := list.entry(1); got.Domain != "b.test" || got.Action != ActionAllow {
		t.Errorf("entry 1 = %+v", got)
	}
	if got := list.entry(4); got.Domain != "last.test" {
		t.Errorf("a final line without a newline was lost: %+v", got)
	}
}
