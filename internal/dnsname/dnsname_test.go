package dnsname

import "testing"

func TestNormalize(t *testing.T) {
	if got := Normalize("  Example.COM. "); got != "example.com" {
		t.Fatalf("Normalize = %q", got)
	}
}

func TestValid(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com":             true,
		"a-b.example.com":         true,
		"":                        false,
		"-bad.example.com":        false,
		"bad-.example.com":        false,
		"double..dot.com":         false,
		"has space.com":           false,
		"slash/example.com":       false,
		string(make([]byte, 254)): false,
	} {
		if got := Valid(name); got != want {
			t.Errorf("Valid(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParent(t *testing.T) {
	if got := Parent("a.b.example.com"); got != "b.example.com" {
		t.Fatalf("Parent = %q", got)
	}
	if got := Parent("com"); got != "" {
		t.Fatalf("Parent(com) = %q", got)
	}
}
