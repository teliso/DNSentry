package app

import (
	"testing"
	"time"
)

func TestUpstreamPoolUsesSingleHalfOpenProbe(t *testing.T) {
	pool := NewUpstreamPool([]string{"one:53", "two:53"})
	pool.mu.Lock()
	for _, address := range pool.addresses {
		pool.states[address].failures = 3
		pool.states[address].unhealthyUntil = time.Now().Add(time.Minute)
	}
	pool.mu.Unlock()

	first := pool.Candidates()
	if len(first) != 1 {
		t.Fatalf("half-open candidate count = %d, want 1", len(first))
	}
	second := pool.Candidates()
	if len(second) != 0 {
		t.Fatalf("concurrent half-open candidate count = %d, want 0", len(second))
	}
	pool.RecordFailure(first[0])
	third := pool.Candidates()
	if len(third) != 1 {
		t.Fatalf("candidate count after probe failure = %d, want 1", len(third))
	}
}

func TestUpstreamPoolUsesExponentialCooldown(t *testing.T) {
	pool := NewUpstreamPool([]string{"one:53"})
	for attempt := 0; attempt < 3; attempt++ {
		pool.RecordFailure("one:53")
	}
	pool.mu.RLock()
	firstCooldown := time.Until(pool.states["one:53"].unhealthyUntil)
	pool.mu.RUnlock()
	if firstCooldown < 29*time.Second || firstCooldown > 31*time.Second {
		t.Fatalf("first cooldown = %s, want about 30s", firstCooldown)
	}
	pool.RecordFailure("one:53")
	pool.mu.RLock()
	secondCooldown := time.Until(pool.states["one:53"].unhealthyUntil)
	pool.mu.RUnlock()
	if secondCooldown < 59*time.Second || secondCooldown > 61*time.Second {
		t.Fatalf("second cooldown = %s, want about 60s", secondCooldown)
	}
}
