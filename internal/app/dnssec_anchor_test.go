package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDNSSECAutoUpdateUsesManagedTrustAnchorFile(t *testing.T) {
	config := testConfig()
	config.DNSSECValidate = true
	config.DNSSECAutoUpdate = true
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if validated.DNSSECTrustAnchorFile != defaultDNSSECTrustAnchorFile || len(validated.DNSSECTrustAnchors) != 0 {
		t.Fatalf("unexpected automatic trust anchor configuration: %#v", validated)
	}
	if _, err := effectiveDNSSECTrustAnchors(*validated); err != nil {
		t.Fatalf("missing automatic trust anchor file should use built-in anchors: %v", err)
	}

	config = testConfig()
	config.DNSSECValidate = true
	config.DNSSECAutoUpdate = true
	config.DNSSECTrustAnchors = []string{". 3600 IN DNSKEY 257 3 13 invalid"}
	if _, err := validateConfig(config); err == nil {
		t.Fatal("automatic trust anchor update accepted manual anchors")
	}
}

func TestDNSSECTrustAnchorFileLoadsValidatedDNSKEY(t *testing.T) {
	_, _, anchor := newTestSignedKey(t, "example.")
	path := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(path, []byte("# managed trust anchor\n"+anchor+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	anchors, err := loadDNSSECTrustAnchorsFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 || anchors[0] != anchor {
		t.Fatalf("unexpected anchors: %#v", anchors)
	}

	config := testConfig()
	config.DNSSECValidate = true
	config.DNSSECTrustAnchorFile = path
	if _, err := validateConfig(config); err != nil {
		t.Fatalf("trust anchor file config rejected: %v", err)
	}
}
