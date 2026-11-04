package dnssec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type stubResolver struct{}

func (stubResolver) Resolve(context.Context, *model.Request) (*model.Response, error) {
	return &model.Response{Res: &dns.Msg{}}, nil
}

// testAnchor is a freshly generated key in DNSKEY presentation format.
func testAnchor(t *testing.T) string {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := key.Generate(256); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key.String()
}

func TestNewValidatorUsesBuiltInAnchorsAndRequiresResolver(t *testing.T) {
	validator, err := NewValidator(context.Background(), nil, stubResolver{})
	if err != nil {
		t.Fatalf("built-in root anchors did not load: %v", err)
	}
	validator.Close()
	validator.Close() // closing twice is harmless
	if _, err := NewValidator(context.Background(), nil, nil); err == nil {
		t.Fatal("a validator without a resolver was created")
	}
}

func TestValidateAnchorsRejectsBadInput(t *testing.T) {
	if err := ValidateAnchors(nil); err != nil {
		t.Fatalf("no anchors means built-in anchors: %v", err)
	}
	for name, anchors := range map[string][]string{
		"empty":    {" "},
		"too long": {strings.Repeat("a", maxAnchorBytes+1)},
		"too many": make([]string, maxAnchors+1),
	} {
		if err := ValidateAnchors(anchors); err == nil {
			t.Errorf("%s: invalid anchors were accepted", name)
		}
	}
	if err := ValidateAnchors([]string{testAnchor(t)}); err != nil {
		t.Fatalf("valid anchor rejected: %v", err)
	}
}

func TestAnchorFileRoundTrip(t *testing.T) {
	anchor := testAnchor(t)
	path := filepath.Join(t.TempDir(), "sub", "root.key")
	if err := WriteAnchorFile(path, []string{anchor}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAnchorsFromFile(path)
	if err != nil || len(loaded) != 1 || loaded[0] != anchor {
		t.Fatalf("round trip = %v, %v", loaded, err)
	}
	if err := WriteAnchorFile(path, nil); err == nil {
		t.Fatal("an empty anchor file was written")
	}
	if err := os.WriteFile(path, []byte("# only a comment\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAnchorsFromFile(path); err == nil {
		t.Fatal("a file without anchors was accepted")
	}
}
