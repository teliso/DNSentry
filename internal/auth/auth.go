// Package auth implements the console login: one user whose password is stored
// as a bcrypt hash, and in-memory browser sessions.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/teliso/DNSentry/internal/fsutil"
)

const (
	MinPasswordLength = 8
	maxPasswordBytes  = 72 // bcrypt ignores everything after this
	maxUsernameLength = 64
)

// Cost is the bcrypt work factor. Only tests lower it.
var Cost = 12

// Store holds the console credentials in a file readable only by the service.
// Its methods are safe for concurrent use and a nil *Store means "no login".
type Store struct {
	path string

	mu       sync.RWMutex
	username string
	hash     []byte
}

type file struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
}

// Exists reports whether credentials have been saved at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Open loads the credentials at path; a missing file means no login is set up.
func Open(path string) (*Store, error) {
	store := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var saved file
	if err := json.Unmarshal(data, &saved); err != nil || saved.Username == "" || saved.Hash == "" {
		return nil, errors.New("login file is damaged: delete it to turn the console login off")
	}
	store.username, store.hash = saved.Username, []byte(saved.Hash)
	return store, nil
}

// Configured reports whether a password is set.
func (s *Store) Configured() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.hash) > 0
}

func (s *Store) Username() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.username
}

// ValidateCredentials checks a new username and password.
func ValidateCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || utf8.RuneCountInString(username) > maxUsernameLength {
		return errors.New("username must be 1 to 64 characters")
	}
	for _, r := range username {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("username must not contain spaces or control characters")
		}
	}
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > maxPasswordBytes {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// Set saves a new username and password.
func (s *Store) Set(username, password string) error {
	if err := ValidateCredentials(username, password); err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), Cost)
	if err != nil {
		return err
	}
	data, err := json.Marshal(file{Username: username, Hash: string(hash)})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fsutil.WriteFileAtomic(s.path, data, 0600); err != nil {
		return err
	}
	s.username, s.hash = username, hash
	return nil
}

// A hash of a random password, compared against when the username is wrong so
// that the time taken does not reveal whether the username exists.
var dummyHash = sync.OnceValue(func() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte("dnsentry-dummy"), Cost)
	return hash
})

// Verify checks the username and password.
func (s *Store) Verify(username, password string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	expectedUser, hash := s.username, s.hash
	s.mu.RUnlock()
	if len(hash) == 0 {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(expectedUser)) == 1
	if !userOK {
		hash = dummyHash()
	}
	passwordOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return userOK && passwordOK
}

// VerifyPassword checks only the password (the caller is already logged in).
func (s *Store) VerifyPassword(password string) bool {
	return s.Verify(s.Username(), password)
}

// Clear removes the credentials, turning the login off.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.username, s.hash = "", nil
	return nil
}

// Sessions are browser logins. Tokens are random, only their hashes are kept,
// and they live in memory: restarting the service logs everybody out.
type Sessions struct {
	mu       sync.Mutex
	expiries map[[32]byte]time.Time
}

const maxSessions = 1000

func NewSessions() *Sessions { return &Sessions{expiries: map[[32]byte]time.Time{}} }

func hashToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// New creates a session valid for ttl and returns its token.
func (s *Sessions) New(ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiry := range s.expiries {
		if now.After(expiry) {
			delete(s.expiries, key)
		}
	}
	if len(s.expiries) >= maxSessions { // drop the session closest to expiring
		var oldest [32]byte
		var oldestExpiry time.Time
		for key, expiry := range s.expiries {
			if oldestExpiry.IsZero() || expiry.Before(oldestExpiry) {
				oldest, oldestExpiry = key, expiry
			}
		}
		delete(s.expiries, oldest)
	}
	s.expiries[hashToken(token)] = now.Add(ttl)
	return token, nil
}

// Valid reports whether token is a live session.
func (s *Sessions) Valid(token string) bool {
	if token == "" {
		return false
	}
	key := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.expiries[key]
	if ok && time.Now().After(expiry) {
		delete(s.expiries, key)
		return false
	}
	return ok
}

func (s *Sessions) Revoke(token string) {
	s.mu.Lock()
	delete(s.expiries, hashToken(token))
	s.mu.Unlock()
}

// RevokeAll logs everybody out (used when the password changes).
func (s *Sessions) RevokeAll() {
	s.mu.Lock()
	clear(s.expiries)
	s.mu.Unlock()
}
