package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestStore(t *testing.T, content string) *Store {
	t.Helper()
	file := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(file)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	return store
}

func mustMatch(t *testing.T, store *Store, domain string, want Action) Entry {
	t.Helper()
	rule, ok := store.Match(domain)
	if !ok || rule.Action != want {
		t.Fatalf("Match(%q) = %#v, %v; want %s", domain, rule, ok, want)
	}
	return rule
}

func TestMatchUsesMostSpecificRule(t *testing.T) {
	store := newTestStore(t, "||example.com^\n@@||safe.example.com^\n")
	mustMatch(t, store, "ads.example.com", ActionBlock)
	mustMatch(t, store, "x.safe.example.com", ActionAllow)
	if _, ok := store.Match("example.org"); ok {
		t.Fatal("unexpected match for unrelated domain")
	}
}

func TestPrecedence(t *testing.T) {
	store := newTestStore(t, "||conflict.example^\n@@||conflict.example^\n||local.example^\n")
	mustMatch(t, store, "conflict.example", ActionAllow) // allow beats block, order independent
	store.SetRemote("https://list", []Entry{{Domain: "local.example", Action: ActionAllow, Source: "https://list"}})
	if rule := mustMatch(t, store, "local.example", ActionBlock); rule.Source != "" {
		t.Fatalf("local rule should win over remote, got %#v", rule)
	}
}

func TestAddAndDeleteEditTheLocalFile(t *testing.T) {
	store := newTestStore(t, "# my rules\n0.0.0.0 a.example b.example")
	if _, err := store.Add("||c.example^", ActionBlock); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("C.example", ActionBlock); !errors.Is(err, ErrRuleExists) {
		t.Fatalf("duplicate add error = %v", err)
	}
	if _, err := store.Add("not a domain", ActionBlock); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("invalid add error = %v", err)
	}
	if err := store.Delete("a.example", ActionBlock); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("a.example", ActionBlock); !errors.Is(err, ErrRuleMissing) {
		t.Fatalf("second delete error = %v", err)
	}
	text, _ := store.LocalText()
	if text != "# my rules\n0.0.0.0 b.example\n||c.example^\n" {
		t.Fatalf("file content = %q", text)
	}
	if _, ok := store.Match("a.example"); ok {
		t.Fatal("deleted rule still matches")
	}
	mustMatch(t, store, "b.example", ActionBlock)
}

func TestSetLocalTextReportsIgnoredLines(t *testing.T) {
	store := newTestStore(t, "")
	summary, err := store.SetLocalText("! header\r\n||a.example^\r\nbad rule here\r\n\r\n@@||b.example^")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Rules != 2 || summary.Ignored != 1 || summary.IgnoredLines[0] != 3 {
		t.Fatalf("summary = %#v", summary)
	}
	text, _ := store.LocalText()
	if strings.Contains(text, "\r") || !strings.HasSuffix(text, "@@||b.example^\n") {
		t.Fatalf("text not normalized: %q", text)
	}
	mustMatch(t, store, "b.example", ActionAllow)
}

func TestQueryAndCheck(t *testing.T) {
	store := newTestStore(t, "||example.com^\n@@||safe.example.com^\n")
	store.SetRemote("https://list", []Entry{
		{Domain: "ads.example.com", Action: ActionBlock, Source: "https://list"},
		{Domain: "other.test", Action: ActionBlock, Source: "https://list"},
	})
	if page := store.Query(Filter{Search: "example", Limit: 2}); page.Total != 3 || len(page.Items) != 2 || page.Items[0].Source != "" {
		t.Fatalf("search page = %#v", page)
	}
	if page := store.Query(Filter{Source: "https://list", Offset: 1}); page.Total != 2 || page.Items[0].Domain != "other.test" {
		t.Fatalf("source page = %#v", page)
	}
	if page := store.Query(Filter{Source: SourceLocal, Action: ActionAllow}); page.Total != 1 {
		t.Fatalf("local allow page = %#v", page)
	}

	check, err := store.Check("x.ads.example.com")
	if err != nil || check.Rule == nil || check.Rule.Domain != "ads.example.com" || len(check.Candidates) != 2 {
		t.Fatalf("check = %#v, %v", check, err)
	}
	if counts := store.Counts(); counts[SourceLocal] != 2 || counts["https://list"] != 2 || store.Len() != 4 {
		t.Fatalf("counts = %v len=%d", counts, store.Len())
	}
}

func TestMatchDuringConcurrentRebuilds(t *testing.T) {
	store := newTestStore(t, "||stable.example^\n")
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 200; index++ {
				if _, ok := store.Match("child.stable.example"); !ok {
					t.Error("stable rule disappeared during a rebuild")
					return
				}
				_ = store.Query(Filter{Search: "remote"})
			}
		}()
	}
	for version := 0; version < 200; version++ {
		store.SetRemote("https://list", []Entry{{Domain: "remote.example", Action: ActionBlock, Source: "https://list"}})
	}
	wait.Wait()
}
