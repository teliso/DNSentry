package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/teliso/DNSentry/internal/dnssec"

	"github.com/0xERR0R/blocky/model"
	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
)

// defaultDNSSECTrustAnchorFile is the managed anchor file, next to the configuration.
func defaultDNSSECTrustAnchorFile() string {
	return filepath.Join(filepath.Dir(configPath()), "dnssec", "root-auto.key")
}

func effectiveDNSSECTrustAnchors(config Config) ([]string, error) {
	if strings.TrimSpace(config.DNSSECTrustAnchorFile) == "" {
		return config.DNSSECTrustAnchors, nil
	}
	anchors, err := dnssec.LoadAnchorsFromFile(config.DNSSECTrustAnchorFile)
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
		path = defaultDNSSECTrustAnchorFile()
	}
	current, err := dnssec.LoadAnchorsFromFile(path)
	if err == nil && strings.Join(current, "\n") == strings.Join(anchors, "\n") {
		return nil
	}
	if err := dnssec.WriteAnchorFile(path, anchors); err != nil {
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

func (s *DNSServer) DNSSECStats() dnssec.Stats {
	s.dnssecMu.RLock()
	validator := s.dnssec
	s.dnssecMu.RUnlock()
	if validator == nil {
		return dnssec.Stats{}
	}
	return validator.Stats()
}

func (s *DNSServer) rebuildDNSSECValidator(config Config) error {
	var replacement *dnssec.Validator
	if config.DNSSECValidate {
		anchors, err := effectiveDNSSECTrustAnchors(config)
		if err != nil {
			return err
		}
		replacement, err = dnssec.NewValidator(context.Background(), anchors, &dnssecUpstream{server: s})
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
