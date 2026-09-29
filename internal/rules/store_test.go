package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuleFormats(t *testing.T) {
	tests := []struct {
		line   string
		domain string
		action Action
		ip     string
	}{
		{"||ads.example.com^", "ads.example.com", ActionBlock, ""},
		{"@@||trusted.example.com^", "trusted.example.com", ActionAllow, ""},
		{"example.net", "example.net", ActionBlock, ""},
		{"0.0.0.0 tracker.example.org", "tracker.example.org", ActionBlock, "0.0.0.0"},
	}
	for _, test := range tests {
		entry, _, ok := parseRule(test.line)
		if !ok || entry.Domain != test.domain || entry.Action != test.action || entry.IP != test.ip {
			t.Fatalf("parseRule(%q) = %#v, ok=%v", test.line, entry, ok)
		}
	}
}

func TestRuleStoreWhitelistOverridesParentBlock(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "rules.txt")
	content := "||example.com^\n@@||safe.example.com^\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	store := NewStore(file)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	if action, _, ok := store.Match("ads.example.com"); !ok || action != ActionBlock {
		t.Fatalf("expected subdomain to be blocked, got %q, %v", action, ok)
	}
	if action, _, ok := store.Match("safe.example.com"); !ok || action != ActionAllow {
		t.Fatalf("expected whitelist to win, got %q, %v", action, ok)
	}
	if _, _, ok := store.Match("example.org"); ok {
		t.Fatal("unexpected match for unrelated domain")
	}
}

func TestRuleStoreSameDomainAllowIsOrderIndependent(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "block then allow", content: "||conflict.example.com^\n@@||conflict.example.com^\n"},
		{name: "allow then block", content: "@@||conflict.example.com^\n||conflict.example.com^\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			file := filepath.Join(directory, "rules.txt")
			if err := os.WriteFile(file, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}

			store := NewStore(file)
			if err := store.Reload(); err != nil {
				t.Fatal(err)
			}
			if action, _, ok := store.Match("conflict.example.com"); !ok || action != ActionAllow {
				t.Fatalf("expected allow to win regardless of order, got %q, %v", action, ok)
			}
		})
	}
}

func TestRuleStoreMoreSpecificRuleOverridesParent(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "rules.txt")
	content := "@@||example.com^\n||ads.example.com^\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	store := NewStore(file)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	if action, _, ok := store.Match("ads.example.com"); !ok || action != ActionBlock {
		t.Fatalf("expected specific block to win over parent allow, got %q, %v", action, ok)
	}
	if action, _, ok := store.Match("other.example.com"); !ok || action != ActionAllow {
		t.Fatalf("expected parent allow for other subdomains, got %q, %v", action, ok)
	}
}
