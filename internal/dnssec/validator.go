// Package dnssec validates DNSSEC signature chains for resolved answers and
// reads and writes root trust anchor files. It performs no network I/O itself:
// DNSKEY and DS lookups go through the Resolver the caller provides.
package dnssec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	maxAnchors     = 32
	maxAnchorBytes = 4096

	// These bounds keep validation work predictable. They are deliberately
	// explicit instead of relying on the library's zero-value defaults.
	cacheExpirationHours uint = 1
	maxChainDepth        uint = 16
	maxNSEC3Iterations   uint = 150
	maxUpstreamQueries   uint = 30
	clockSkewSeconds     uint = 3600
)

// Stats is intentionally a fixed, low-cardinality snapshot suitable for
// exposing from the status endpoint without putting domain names in metrics.
type Stats struct {
	Secure        uint64 `json:"secure"`
	Insecure      uint64 `json:"insecure"`
	Bogus         uint64 `json:"bogus"`
	Indeterminate uint64 `json:"indeterminate"`
}

// Validator owns the blocky validator and its lifecycle. Keeping this
// wrapper independent from DNSServer makes it explicit that only the existing
// upstream abstraction is used for DNSKEY and DS lookups.
type Validator struct {
	validator *blockydnssec.Validator
	cancel    context.CancelFunc
	closeOnce sync.Once

	secure        atomic.Uint64
	insecure      atomic.Uint64
	bogus         atomic.Uint64
	indeterminate atomic.Uint64
}

func ValidateAnchors(anchors []string) error {
	if len(anchors) > maxAnchors {
		return fmt.Errorf("dnssec_trust_anchors must contain at most %d records", maxAnchors)
	}
	for index, anchor := range anchors {
		if strings.TrimSpace(anchor) == "" {
			return fmt.Errorf("dnssec_trust_anchors[%d] must not be empty", index)
		}
		if len(anchor) > maxAnchorBytes {
			return fmt.Errorf("dnssec_trust_anchors[%d] exceeds %d bytes", index, maxAnchorBytes)
		}
	}
	if len(anchors) == 0 {
		return nil // The validator will load the IANA root anchors.
	}
	if _, err := blockydnssec.NewTrustAnchorStore(anchors); err != nil {
		return fmt.Errorf("invalid dnssec_trust_anchors: %w", err)
	}
	return nil
}

func LoadAnchorsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	anchors := make([]string, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxAnchorBytes)
	for scanner.Scan() {
		anchor := strings.TrimSpace(scanner.Text())
		if anchor == "" || strings.HasPrefix(anchor, "#") || strings.HasPrefix(anchor, ";") {
			continue
		}
		anchors = append(anchors, anchor)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(anchors) == 0 {
		return nil, errors.New("trust anchor file contains no DNSKEY records")
	}
	if err := ValidateAnchors(anchors); err != nil {
		return nil, err
	}
	return anchors, nil
}

func WriteAnchorFile(path string, anchors []string) error {
	if len(anchors) == 0 {
		return errors.New("cannot write an empty trust anchor file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".root-auto.key.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, strings.Join(anchors, "\n")+"\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		if err := os.Rename(temporaryPath, path); err != nil {
			return err
		}
	}
	committed = true
	return nil
}

// NewValidator creates a validator with bounded resource usage. A nil
// anchor list intentionally selects blocky's built-in IANA root trust anchors.
func NewValidator(parent context.Context, anchors []string, upstream blockydnssec.Resolver) (*Validator, error) {
	if upstream == nil {
		return nil, errors.New("DNSSEC validator requires an upstream resolver")
	}
	if err := ValidateAnchors(anchors); err != nil {
		return nil, err
	}
	trustAnchors, err := blockydnssec.NewTrustAnchorStore(anchors)
	if err != nil {
		return nil, fmt.Errorf("create DNSSEC trust anchor store: %w", err)
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)

	// The library logs validation warnings through logrus. Use a private logger
	// that is permanently discarded so DNSSEC cannot pollute application logs.
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.PanicLevel)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	return &Validator{
		validator: blockydnssec.NewValidator(
			ctx,
			trustAnchors,
			logrus.NewEntry(logger),
			upstream,
			cacheExpirationHours,
			maxChainDepth,
			maxNSEC3Iterations,
			maxUpstreamQueries,
			clockSkewSeconds,
		),
		cancel: cancel,
	}, nil
}

func (v *Validator) Validate(ctx context.Context, response *dns.Msg, question dns.Question) blockydnssec.ValidationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := v.validator.ValidateResponse(ctx, response, question)
	switch result {
	case blockydnssec.ValidationResultSecure:
		v.secure.Add(1)
	case blockydnssec.ValidationResultInsecure:
		v.insecure.Add(1)
	case blockydnssec.ValidationResultBogus:
		v.bogus.Add(1)
	case blockydnssec.ValidationResultIndeterminate:
		v.indeterminate.Add(1)
	}
	return result
}

func (v *Validator) Stats() Stats {
	if v == nil {
		return Stats{}
	}
	return Stats{
		Secure:        v.secure.Load(),
		Insecure:      v.insecure.Load(),
		Bogus:         v.bogus.Load(),
		Indeterminate: v.indeterminate.Load(),
	}
}

func (v *Validator) Close() {
	if v == nil {
		return
	}
	v.closeOnce.Do(func() {
		v.cancel()
	})
}

// dnssecUpstream adapts the server's existing upstream exchange path to
// blocky's minimal resolver interface. It deliberately never calls ServeDNS.
