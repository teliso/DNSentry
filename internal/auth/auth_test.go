package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	Cost = bcrypt.MinCost
	os.Exit(m.Run())
}

func TestStoreSetVerifyClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := Open(path)
	if err != nil || store.Configured() {
		t.Fatalf("fresh store: %v configured=%v", err, store.Configured())
	}
	if err := store.Set("admin", "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	if err := store.Set("bad name", "long-enough-password"); err == nil {
		t.Fatal("a username with a space was accepted")
	}
	if err := store.Set("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credentials file: %v %v", info, err)
	}
	if data, _ := os.ReadFile(path); string(data) == "" || strings.Contains(string(data), "correct horse battery") {
		t.Fatalf("the password is stored in the clear: %s", data)
	}
	if !store.Verify("admin", "correct horse battery") || !store.Verify(" admin ", "correct horse battery") {
		t.Fatal("the right credentials were rejected")
	}
	if store.Verify("admin", "wrong") || store.Verify("other", "correct horse battery") || store.Verify("", "") {
		t.Fatal("wrong credentials were accepted")
	}

	reopened, err := Open(path)
	if err != nil || !reopened.Configured() || reopened.Username() != "admin" || !reopened.VerifyPassword("correct horse battery") {
		t.Fatalf("reopened store: %v", err)
	}
	if err := reopened.Clear(); err != nil || reopened.Configured() || Exists(path) {
		t.Fatalf("clear: %v", err)
	}
	var nilStore *Store
	if nilStore.Configured() || nilStore.Verify("a", "b") || nilStore.Username() != "" {
		t.Fatal("a nil store must behave as 'no login'")
	}
}

func TestOpenRejectsDamagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("a damaged login file was accepted")
	}
}

func TestSessions(t *testing.T) {
	sessions := NewSessions()
	token, err := sessions.New(time.Hour)
	if err != nil || len(token) < 40 || !sessions.Valid(token) {
		t.Fatalf("new session: %q %v", token, err)
	}
	if sessions.Valid("") || sessions.Valid("not-a-token") {
		t.Fatal("an unknown token was valid")
	}
	other, _ := sessions.New(time.Hour)
	sessions.Revoke(token)
	if sessions.Valid(token) || !sessions.Valid(other) {
		t.Fatal("revoking one session must not affect another")
	}
	sessions.RevokeAll()
	if sessions.Valid(other) {
		t.Fatal("RevokeAll left a session alive")
	}
	expired, _ := sessions.New(time.Nanosecond)
	time.Sleep(5 * time.Millisecond)
	if sessions.Valid(expired) {
		t.Fatal("an expired session was valid")
	}
}
