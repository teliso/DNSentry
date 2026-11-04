package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetupPaths(t *testing.T) {
	start, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	original := configFile
	t.Cleanup(func() {
		_ = os.Chdir(start)
		configFile = original
	})
	base := t.TempDir()
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(base)

	// Neither given: the historical default under the current directory.
	configFile = filepath.Join("data", "config.yaml")
	if err := SetupPaths("", ""); err != nil || configFile != filepath.Join("data", "config.yaml") {
		t.Fatalf("default: %q %v", configFile, err)
	}

	// -data-dir moves the working directory and the default configuration into it.
	data := filepath.Join(base, "state", "dnsentry")
	if err := SetupPaths("", data); err != nil {
		t.Fatal(err)
	}
	if wd, _ := os.Getwd(); wd != filepath.Join(resolved, "state", "dnsentry") && wd != data {
		t.Fatalf("working directory = %q", wd)
	}
	if configFile != filepath.Join(data, "config.yaml") {
		t.Fatalf("config = %q", configFile)
	}
	if info, err := os.Stat(data); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("data directory: %v %v", info, err)
	}
	if got := defaultConfig().RulesFile; got != filepath.Join(data, "rules.txt") {
		t.Fatalf("rules file default = %q", got)
	}
	if got := defaultDNSSECTrustAnchorFile(); got != filepath.Join(data, "dnssec", "root-auto.key") {
		t.Fatalf("anchor file default = %q", got)
	}

	// An explicit -config is resolved against the directory the program started in, before the move.
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	if err := SetupPaths(filepath.Join("etc", "dns.yaml"), data); err != nil {
		t.Fatal(err)
	}
	if configFile != filepath.Join(resolved, "etc", "dns.yaml") && configFile != filepath.Join(base, "etc", "dns.yaml") {
		t.Fatalf("explicit config = %q", configFile)
	}
}
