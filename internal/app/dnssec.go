package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/0xERR0R/blocky/model"
	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
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

// NewDNSSECValidator creates a validator with bounded resource usage. A nil
// anchor list intentionally selects blocky's built-in IANA root trust anchors.
func NewDNSSECValidator(parent context.Context, anchors []string, upstream blockydnssec.Resolver) (*DNSSECValidator, error) {
	if upstream == nil {
		return nil, errors.New("DNSSEC validator requires an upstream resolver")
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
		var err error
		replacement, err = NewDNSSECValidator(context.Background(), nil, &dnssecUpstream{server: s})
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
