package upstream

import (
	"testing"
	"time"
)

func TestUpstreamPoolUsesSingleHalfOpenProbe(t *testing.T) {
	pool := NewPool([]string{"one:53", "two:53"})
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
	pool := NewPool([]string{"one:53"})
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

func TestUpstreamPoolMarksFailedServers(t *testing.T) {
	pool := NewPool([]string{"one:53", "two:53"})
	pool.RecordFailure("one:53")
	pool.RecordFailure("one:53")
	pool.RecordFailure("one:53")
	candidates := pool.Candidates()
	if len(candidates) != 1 || candidates[0] != "two:53" {
		t.Fatalf("expected failed upstream to be skipped, got %#v", candidates)
	}
	pool.RecordSuccess("one:53", 15*time.Millisecond)
	if health := pool.Health()[0]; !health.Healthy || health.Failures != 0 || health.LatencyMS != 15 {
		t.Fatalf("expected recovered upstream, got %#v", health)
	}
}

func TestUpstreamHistoryAggregatesPerMinute(t *testing.T) {
	state := &upstreamState{}
	base := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	state.record(base, 10*time.Millisecond, true)
	state.record(base.Add(5*time.Second), 30*time.Millisecond, true)
	state.record(base.Add(10*time.Second), 0, false)
	state.record(base.Add(2*time.Minute), 50*time.Millisecond, true)

	now := base.Add(2*time.Minute + 5*time.Second)
	points := state.points(now)
	if len(points) != historyMinutes {
		t.Fatalf("points = %d, want %d", len(points), historyMinutes)
	}
	first, last := points[historyMinutes-3], points[historyMinutes-1]
	if first.Requests != 3 || first.Failures != 1 || first.AverageLatencyMS != 20 {
		t.Fatalf("first minute = %#v", first)
	}
	if idle := points[historyMinutes-2]; idle.Requests != 0 {
		t.Fatalf("idle minute = %#v", idle)
	}
	if last.Requests != 1 || last.AverageLatencyMS != 50 {
		t.Fatalf("last minute = %#v", last)
	}
	// A bucket reused 30 minutes later starts fresh.
	state.record(base.Add(historyMinutes*time.Minute), 7*time.Millisecond, true)
	points = state.points(base.Add(historyMinutes * time.Minute))
	if latest := points[historyMinutes-1]; latest.Requests != 1 || latest.AverageLatencyMS != 7 {
		t.Fatalf("reused bucket = %#v", latest)
	}
}

func TestPoolHealthIncludesHistory(t *testing.T) {
	pool := NewPool([]string{"one:53"})
	pool.RecordSuccess("one:53", 12*time.Millisecond)
	pool.RecordFailure("one:53")
	history := pool.Health()[0].History
	if len(history) != historyMinutes {
		t.Fatalf("history length = %d", len(history))
	}
	var requests, failures uint32 // summed: the two calls may straddle a minute boundary
	for _, point := range history {
		requests += point.Requests
		failures += point.Failures
	}
	if requests != 2 || failures != 1 {
		t.Fatalf("requests=%d failures=%d, want 2 and 1", requests, failures)
	}
}
