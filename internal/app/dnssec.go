package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/model"
	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const defaultDNSSECTrustAnchorFile = "data/dnssec/root-auto.key"

const (
	maxDNSSECTrustAnchors     = 32
	maxDNSSECTrustAnchorBytes = 4096

	// These bounds keep validation work predictable. They are deliberately
	// explicit instead of relying on the library's zero-value defaults.
	dnssecCacheExpirationHours uint = 1
	dnssecMaxChainDepth        uint = 16
	dnssecMaxNSEC3Iterations   uint = 150
	dnssecMaxUpstreamQueries   uint = 30
	dnssecClockSkewSeconds     uint = 3600
)

// DNSSECStats is intentionally a fixed, low-cardinality snapshot suitable for
// exposing from the status endpoint without putting domain names in metrics.
type DNSSECStats struct {
	Secure        uint64 `json:"secure"`
	Insecure      uint64 `json:"insecure"`
	Bogus         uint64 `json:"bogus"`
	Indeterminate uint64 `json:"indeterminate"`
}

// DNSSECValidator owns the blocky validator and its lifecycle. Keeping this
// wrapper independent from DNSServer makes it explicit that only the existing
// upstream abstraction is used for DNSKEY and DS lookups.
type DNSSECValidator struct {
	validator *blockydnssec.Validator
	cancel    context.CancelFunc
	closeOnce sync.Once

	secure        atomic.Uint64
	insecure      atomic.Uint64
	bogus         atomic.Uint64
	indeterminate atomic.Uint64
}

func validateDNSSECTrustAnchors(anchors []string) error {
	if len(anchors) > maxDNSSECTrustAnchors {
		return fmt.Errorf("dnssec_trust_anchors must contain at most %d records", maxDNSSECTrustAnchors)
	}
	for index, anchor := range anchors {
		if strings.TrimSpace(anchor) == "" {
			return fmt.Errorf("dnssec_trust_anchors[%d] must not be empty", index)
		}
		if len(anchor) > maxDNSSECTrustAnchorBytes {
			return fmt.Errorf("dnssec_trust_anchors[%d] exceeds %d bytes", index, maxDNSSECTrustAnchorBytes)
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

func loadDNSSECTrustAnchorsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	anchors := make([]string, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxDNSSECTrustAnchorBytes)
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
	if err := validateDNSSECTrustAnchors(anchors); err != nil {
		return nil, err
	}
	return anchors, nil
}

func effectiveDNSSECTrustAnchors(config Config) ([]string, error) {
	if strings.TrimSpace(config.DNSSECTrustAnchorFile) == "" {
		return config.DNSSECTrustAnchors, nil
	}
	anchors, err := loadDNSSECTrustAnchorsFromFile(config.DNSSECTrustAnchorFile)
	if err != nil {
		if config.DNSSECAutoUpdate {
			return nil, nil
		}
		return nil, fmt.Errorf("load dnssec trust anchor file: %w", err)
	}
	return anchors, nil
}

func (s *DNSServer) watchDNSSECTrustAnchorFile(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var activePath string
	var loadedModTime time.Time
	var nextAutoUpdate time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		config := s.configSnapshot()
		now := time.Now()
		if config.DNSSECValidate && config.DNSSECAutoUpdate && !now.Before(nextAutoUpdate) {
			if err := s.refreshDNSSECTrustAnchors(config); err != nil {
				slog.Warn("DNSSEC trust anchor update skipped", "error", err)
				nextAutoUpdate = now.Add(5 * time.Minute)
			} else {
				nextAutoUpdate = now.Add(24 * time.Hour)
			}
		}
		path := strings.TrimSpace(config.DNSSECTrustAnchorFile)
		if !config.DNSSECValidate || path == "" || config.DNSSECAutoUpdate {
			if path == "" {
				activePath = ""
				loadedModTime = time.Time{}
			}
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if path == activePath && !info.ModTime().After(loadedModTime) {
			continue
		}
		if err := s.rebuildDNSSECValidator(config); err != nil {
			slog.Warn("DNSSEC trust anchor reload skipped", "error", err)
			continue
		}
		activePath = path
		loadedModTime = info.ModTime()
	}
}

func (s *DNSServer) refreshDNSSECTrustAnchors(config Config) error {
	request := new(dns.Msg)
	request.SetQuestion(".", dns.TypeDNSKEY)
	ensureDNSSECRequest(request)
	request.CheckingDisabled = true
	response, _, err := s.exchange(request)
	if err != nil {
		return fmt.Errorf("query root DNSKEY: %w", err)
	}
	validation := s.validateDNSSEC(response, request.Question[0])
	if validation != blockydnssec.ValidationResultSecure {
		return fmt.Errorf("root DNSKEY validation returned %s", validation.String())
	}
	anchors := make([]string, 0)
	seen := make(map[string]struct{})
	for _, answer := range response.Answer {
		key, ok := answer.(*dns.DNSKEY)
		if !ok || key.Flags&257 != 257 || key.Flags&0x80 != 0 {
			continue
		}
		anchor := key.String()
		if _, exists := seen[anchor]; exists {
			continue
		}
		seen[anchor] = struct{}{}
		anchors = append(anchors, anchor)
	}
	if len(anchors) == 0 {
		return errors.New("validated root DNSKEY response contains no SEP keys")
	}
	sort.Strings(anchors)
	path := strings.TrimSpace(config.DNSSECTrustAnchorFile)
	if path == "" {
		path = defaultDNSSECTrustAnchorFile
	}
	current, err := loadDNSSECTrustAnchorsFromFile(path)
	if err == nil && strings.Join(current, "\n") == strings.Join(anchors, "\n") {
		return nil
	}
	if err := writeDNSSECTrustAnchorFile(path, anchors); err != nil {
		return err
	}
	next := config
	next.DNSSECTrustAnchorFile = path
	next.DNSSECTrustAnchors = nil
	if err := s.rebuildDNSSECValidator(next); err != nil {
		return fmt.Errorf("activate new root DNSKEY anchors: %w", err)
	}
	return nil
}

func writeDNSSECTrustAnchorFile(path string, anchors []string) error {
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

// NewDNSSECValidator creates a validator with bounded resource usage. A nil
// anchor list intentionally selects blocky's built-in IANA root trust anchors.
func NewDNSSECValidator(parent context.Context, anchors []string, upstream blockydnssec.Resolver) (*DNSSECValidator, error) {
	if upstream == nil {
		return nil, errors.New("DNSSEC validator requires an upstream resolver")
	}
	if err := validateDNSSECTrustAnchors(anchors); err != nil {
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

	return &DNSSECValidator{
		validator: blockydnssec.NewValidator(
			ctx,
			trustAnchors,
			logrus.NewEntry(logger),
			upstream,
			dnssecCacheExpirationHours,
			dnssecMaxChainDepth,
			dnssecMaxNSEC3Iterations,
			dnssecMaxUpstreamQueries,
			dnssecClockSkewSeconds,
		),
		cancel: cancel,
	}, nil
}

func (v *DNSSECValidator) Validate(ctx context.Context, response *dns.Msg, question dns.Question) blockydnssec.ValidationResult {
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

func (v *DNSSECValidator) Stats() DNSSECStats {
	if v == nil {
		return DNSSECStats{}
	}
	return DNSSECStats{
		Secure:        v.secure.Load(),
		Insecure:      v.insecure.Load(),
		Bogus:         v.bogus.Load(),
		Indeterminate: v.indeterminate.Load(),
	}
}

func (v *DNSSECValidator) Close() {
	if v == nil {
		return
	}
	v.closeOnce.Do(func() {
		v.cancel()
	})
}

// dnssecUpstream adapts the server's existing upstream exchange path to
// blocky's minimal resolver interface. It deliberately never calls ServeDNS.
type dnssecUpstream struct {
	server *DNSServer
}

var _ blockydnssec.Resolver = (*dnssecUpstream)(nil)

func (u *dnssecUpstream) Resolve(_ context.Context, request *model.Request) (*model.Response, error) {
	if u == nil || u.server == nil || request == nil || request.Req == nil {
		return nil, errors.New("invalid DNSSEC upstream request")
	}
	if len(request.Req.Question) != 1 {
		return nil, errors.New("DNSSEC upstream request must contain one question")
	}
	query := request.Req.Copy()
	ensureDNSSECRequest(query)
	query.CheckingDisabled = true
	response, _, err := u.server.exchange(query)
	if err != nil {
		return nil, err
	}
	return &model.Response{Res: response}, nil
}

func (s *DNSServer) markDNSSECCache(key string, secure bool) {
	if key == "" {
		return
	}
	s.dnssecCacheMu.Lock()
	defer s.dnssecCacheMu.Unlock()
	if s.dnssecCacheOK == nil {
		s.dnssecCacheOK = make(map[string]struct{})
	}
	if secure {
		s.dnssecCacheOK[key] = struct{}{}
	} else {
		delete(s.dnssecCacheOK, key)
	}
}

func (s *DNSServer) cachedDNSSECIsSecure(key string) bool {
	s.dnssecCacheMu.Lock()
	_, ok := s.dnssecCacheOK[key]
	s.dnssecCacheMu.Unlock()
	return ok
}

func (s *DNSServer) clearDNSSECCacheMarks() {
	s.dnssecCacheMu.Lock()
	s.dnssecCacheOK = make(map[string]struct{})
	s.dnssecCacheMu.Unlock()
}

func (s *DNSServer) DNSSECStats() DNSSECStats {
	s.dnssecMu.RLock()
	validator := s.dnssec
	s.dnssecMu.RUnlock()
	if validator == nil {
		return DNSSECStats{}
	}
	return validator.Stats()
}

func (s *DNSServer) rebuildDNSSECValidator(config Config) error {
	var replacement *DNSSECValidator
	if config.DNSSECValidate {
		anchors, err := effectiveDNSSECTrustAnchors(config)
		if err != nil {
			return err
		}
		replacement, err = NewDNSSECValidator(context.Background(), anchors, &dnssecUpstream{server: s})
		if err != nil {
			return err
		}
	}

	s.dnssecMu.Lock()
	old := s.dnssec
	s.dnssec = replacement
	s.dnssecMu.Unlock()
	if old != nil {
		old.Close()
	}
	s.clearDNSSECCacheMarks()
	return nil
}

func (s *DNSServer) closeDNSSECValidator() {
	s.dnssecMu.Lock()
	old := s.dnssec
	s.dnssec = nil
	s.dnssecMu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (s *DNSServer) validateDNSSEC(response *dns.Msg, question dns.Question) blockydnssec.ValidationResult {
	s.dnssecMu.RLock()
	validator := s.dnssec
	s.dnssecMu.RUnlock()
	if validator == nil {
		return blockydnssec.ValidationResultIndeterminate
	}
	return validator.Validate(context.Background(), response, question)
}

func isDNSSECValidationFailure(result blockydnssec.ValidationResult) bool {
	return result == blockydnssec.ValidationResultBogus || result == blockydnssec.ValidationResultIndeterminate
}
