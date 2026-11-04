// Package access decides which clients may use the resolver: allow and deny
// lists, per-client rate limiting and DNS rebinding protection.
package access

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/dnsname"
)

const maxRateLimitQPS = 1_000_000

// Config is the access section of the configuration.
type Config struct {
	AllowedClients        []string `json:"allowed_clients,omitempty" yaml:"allowed_clients,omitempty"`
	DeniedClients         []string `json:"denied_clients,omitempty" yaml:"denied_clients,omitempty"`
	ClientRateLimitQPS    int      `json:"client_rate_limit_qps" yaml:"client_rate_limit_qps"`
	MaxConcurrentQueries  int      `json:"max_concurrent_queries" yaml:"max_concurrent_queries"`
	RebindingProtection   bool     `json:"rebinding_protection" yaml:"rebinding_protection"`
	RebindingAllowDomains []string `json:"rebinding_allow_domains,omitempty" yaml:"rebinding_allow_domains,omitempty"`
}

// Policy is the compiled form of the allow and deny lists.
type Policy struct {
	allowed      []netip.Prefix
	denied       []netip.Prefix
	rebinding    bool
	allowDomains []string
}

func Validate(config Config) error {
	if config.ClientRateLimitQPS < 0 || config.ClientRateLimitQPS > maxRateLimitQPS {
		return fmt.Errorf("client_rate_limit_qps must be between 0 and %d", maxRateLimitQPS)
	}
	if config.MaxConcurrentQueries < 0 {
		return errors.New("max_concurrent_queries must not be negative")
	}
	for _, value := range append(append([]string(nil), config.AllowedClients...), config.DeniedClients...) {
		if _, err := parseClientPrefix(value); err != nil {
			return err
		}
	}
	for index, domain := range config.RebindingAllowDomains {
		domain = dnsname.Normalize(domain)
		if !dnsname.Valid(domain) {
			return fmt.Errorf("invalid rebinding_allow_domains[%d]", index)
		}
	}
	return nil
}

func parseClientPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("client access address must not be empty")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		bits := address.BitLen()
		if bits == 0 {
			return netip.Prefix{}, errors.New("client access address has an invalid address family")
		}
		return netip.PrefixFrom(address, bits), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, errors.New("invalid client access address " + value + ": expected IP or CIDR")
	}
	return prefix.Masked(), nil
}

func Equal(left, right Config) bool {
	return slices.Equal(left.AllowedClients, right.AllowedClients) &&
		slices.Equal(left.DeniedClients, right.DeniedClients) &&
		left.ClientRateLimitQPS == right.ClientRateLimitQPS &&
		left.MaxConcurrentQueries == right.MaxConcurrentQueries &&
		left.RebindingProtection == right.RebindingProtection &&
		slices.Equal(left.RebindingAllowDomains, right.RebindingAllowDomains)
}

func NewPolicy(config Config) *Policy {
	policy := &Policy{rebinding: config.RebindingProtection}
	for _, value := range config.AllowedClients {
		if prefix, err := parseClientPrefix(value); err == nil {
			policy.allowed = append(policy.allowed, prefix)
		}
	}
	for _, value := range config.DeniedClients {
		if prefix, err := parseClientPrefix(value); err == nil {
			policy.denied = append(policy.denied, prefix)
		}
	}
	for _, domain := range config.RebindingAllowDomains {
		domain = dnsname.Normalize(domain)
		if dnsname.Valid(domain) {
			policy.allowDomains = append(policy.allowDomains, domain)
		}
	}
	sort.Strings(policy.allowDomains)
	return policy
}

func (p *Policy) Allows(client string) bool {
	if p == nil {
		return true
	}
	address, err := netip.ParseAddr(strings.TrimSpace(client))
	if err != nil {
		return len(p.allowed) == 0
	}
	for _, prefix := range p.denied {
		if prefix.Contains(address) {
			return false
		}
	}
	if len(p.allowed) == 0 {
		return true
	}
	for _, prefix := range p.allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (p *Policy) AllowsRebindingDomain(domain string) bool {
	if p == nil || !p.rebinding {
		return true
	}
	domain = dnsname.Normalize(domain)
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		for _, allowed := range p.allowDomains {
			if candidate == allowed {
				return true
			}
		}
	}
	return false
}

type clientRateState struct {
	tokens float64
	last   time.Time
}

// Limiter is a per-client token bucket.
type Limiter struct {
	mu       sync.Mutex
	states   map[string]clientRateState
	qps      int
	maxItems int
}

func NewLimiter(qps int) *Limiter {
	limiter := &Limiter{states: make(map[string]clientRateState), maxItems: 8192}
	limiter.SetQPS(qps)
	return limiter
}

func (l *Limiter) SetQPS(qps int) {
	l.mu.Lock()
	l.qps = qps
	if qps <= 0 {
		clear(l.states)
	}
	l.mu.Unlock()
}

func (l *Limiter) Allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.qps <= 0 {
		return true
	}
	now := time.Now()
	state, exists := l.states[client]
	if !exists {
		if len(l.states) >= l.maxItems {
			l.evictOneLocked()
		}
		state = clientRateState{tokens: float64(l.qps * 2), last: now}
	}
	capacity := float64(l.qps) * 2
	state.tokens += now.Sub(state.last).Seconds() * float64(l.qps)
	if state.tokens > capacity {
		state.tokens = capacity
	}
	state.last = now
	if state.tokens < 1 {
		l.states[client] = state
		return false
	}
	state.tokens--
	l.states[client] = state
	return true
}

func (l *Limiter) evictOneLocked() {
	var oldestClient string
	var oldest time.Time
	for client, state := range l.states {
		if oldestClient == "" || state.last.Before(oldest) {
			oldestClient = client
			oldest = state.last
		}
	}
	if oldestClient != "" {
		delete(l.states, oldestClient)
	}
}

func isPrivateDNSAddress(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified())
}

func FilterRebinding(response *dns.Msg, question dns.Question, policy *Policy) (*dns.Msg, bool) {
	if response == nil || policy == nil || !policy.rebinding || policy.AllowsRebindingDomain(question.Name) {
		return response, false
	}
	blocked := false
	filtered := response.Copy()
	filterRecords := func(records []dns.RR) []dns.RR {
		kept := records[:0]
		for _, record := range records {
			private := false
			switch value := record.(type) {
			case *dns.A:
				private = isPrivateDNSAddress(value.A)
			case *dns.AAAA:
				private = isPrivateDNSAddress(value.AAAA)
			}
			if private {
				blocked = true
				continue
			}
			kept = append(kept, record)
		}
		return kept
	}
	filtered.Answer = filterRecords(filtered.Answer)
	filtered.Ns = filterRecords(filtered.Ns)
	filtered.Extra = filterRecords(filtered.Extra)
	if !blocked {
		return response, false
	}
	filtered.Rcode = dns.RcodeServerFailure
	filtered.Answer = nil
	filtered.Ns = nil
	filtered.Extra = nil
	filtered.AuthenticatedData = false
	return filtered, true
}
