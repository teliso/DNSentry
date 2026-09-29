package app

import (
	"sync"
	"sync/atomic"
	"time"
)

type UpstreamHealth struct {
	Address     string `json:"address"`
	Healthy     bool   `json:"healthy"`
	Failures    int    `json:"failures"`
	Requests    uint64 `json:"requests"`
	Successes   uint64 `json:"successes"`
	LatencyMS   int64  `json:"latency_ms"`
	LastSuccess string `json:"last_success,omitempty"`
	LastFailure string `json:"last_failure,omitempty"`
}

type upstreamState struct {
	address        string
	failures       int
	unhealthyUntil time.Time
	latency        time.Duration
	requests       uint64
	successes      uint64
	lastSuccess    time.Time
	lastFailure    time.Time
}

type UpstreamPool struct {
	mu            sync.RWMutex
	states        map[string]*upstreamState
	addresses     []string
	next          atomic.Uint64
	probeInFlight bool
}

func NewUpstreamPool(addresses []string) *UpstreamPool {
	pool := &UpstreamPool{states: make(map[string]*upstreamState)}
	pool.Set(addresses)
	return pool
}

func (p *UpstreamPool) Set(addresses []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := make(map[string]struct{}, len(addresses))
	ordered := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address == "" {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		ordered = append(ordered, address)
		if _, exists := p.states[address]; !exists {
			p.states[address] = &upstreamState{address: address}
		}
	}
	for address := range p.states {
		if _, exists := seen[address]; !exists {
			delete(p.states, address)
		}
	}
	p.addresses = ordered
	p.probeInFlight = false
}

func (p *UpstreamPool) Candidates() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addresses) == 0 {
		return nil
	}
	start := int(p.next.Add(1)-1) % len(p.addresses)
	healthy := make([]string, 0, len(p.addresses))
	now := time.Now()
	for offset := 0; offset < len(p.addresses); offset++ {
		address := p.addresses[(start+offset)%len(p.addresses)]
		state := p.states[address]
		if state == nil || now.After(state.unhealthyUntil) {
			healthy = append(healthy, address)
		}
	}
	if len(healthy) > 0 {
		return healthy
	}
	// When every upstream is cooling down, allow exactly one half-open probe.
	// Other concurrent callers receive no candidate instead of creating a
	// recovery storm against every failed endpoint.
	if p.probeInFlight {
		return nil
	}
	var probe *upstreamState
	for _, address := range p.addresses {
		state := p.states[address]
		if state == nil {
			continue
		}
		if probe == nil || state.unhealthyUntil.Before(probe.unhealthyUntil) {
			probe = state
		}
	}
	if probe == nil {
		return nil
	}
	p.probeInFlight = true
	return []string{probe.address}
}

func (p *UpstreamPool) RecordSuccess(address string, latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.states[address]
	if !ok {
		return
	}
	state.failures = 0
	state.unhealthyUntil = time.Time{}
	p.probeInFlight = false
	state.requests++
	state.successes++
	state.latency = latency
	state.lastSuccess = time.Now()
}

func (p *UpstreamPool) RecordFailure(address string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.states[address]
	if !ok {
		return
	}
	state.failures++
	state.lastFailure = time.Now()
	p.probeInFlight = false
	state.requests++
	if state.failures >= 3 {
		cooldown := 30 * time.Second
		shift := state.failures - 3
		if shift > 4 {
			shift = 4
		}
		cooldown *= time.Duration(1 << shift)
		if cooldown > 5*time.Minute {
			cooldown = 5 * time.Minute
		}
		state.unhealthyUntil = time.Now().Add(cooldown)
	}
}

func (p *UpstreamPool) Health() []UpstreamHealth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]UpstreamHealth, 0, len(p.addresses))
	now := time.Now()
	for _, address := range p.addresses {
		state := p.states[address]
		if state == nil {
			continue
		}
		result = append(result, UpstreamHealth{
			Address:     address,
			Healthy:     now.After(state.unhealthyUntil),
			Failures:    state.failures,
			Requests:    state.requests,
			Successes:   state.successes,
			LatencyMS:   state.latency.Milliseconds(),
			LastSuccess: formatOptionalTime(state.lastSuccess),
			LastFailure: formatOptionalTime(state.lastFailure),
		})
	}
	return result
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}
