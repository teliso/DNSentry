package app

import (
	"os"
	"strings"
	"testing"

	"github.com/teliso/DNSentry/internal/auth"
)

func TestImportConfigPasswordAcceptsShortPasswordAndScrubsFile(t *testing.T) {
	auth.Cost = 4
	dir := t.TempDir()
	previous := configFile
	configFile = dir + "/config.yaml"
	t.Cleanup(func() { configFile = previous })
	yamlText := "dns:\n  upstreams: [1.1.1.1]\nweb:\n  listen: 127.0.0.1:8080\n  auth:\n    username: root\n    password: abc\n"
	if err := os.WriteFile(configPath(), []byte(yamlText), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(authFilePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := importConfigPassword(store); err != nil {
		t.Fatal(err)
	}
	if !store.Verify("root", "abc") {
		t.Fatal("short password from config file should work")
	}
	data, _ := os.ReadFile(configPath())
	if strings.Contains(string(data), "abc") || strings.Contains(string(data), "password") {
		t.Fatalf("password left in config file:\n%s", data)
	}
	if !strings.Contains(string(data), "127.0.0.1:8080") {
		t.Fatalf("config file damaged:\n%s", data)
	}
}
