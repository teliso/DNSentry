package app

import "github.com/teliso/DNSentry/internal/access"

func (s *DNSServer) configureAccess(config access.Config) {
	policy := access.NewPolicy(config)
	s.accessMu.Lock()
	s.accessPolicy = policy
	if s.clientLimiter == nil {
		s.clientLimiter = access.NewLimiter(config.ClientRateLimitQPS)
	} else {
		s.clientLimiter.SetQPS(config.ClientRateLimitQPS)
	}
	s.accessMu.Unlock()
	s.maxConcurrentQueries.Store(int64(config.MaxConcurrentQueries))
}

func (s *DNSServer) accessPolicySnapshot() *access.Policy {
	s.accessMu.RLock()
	defer s.accessMu.RUnlock()
	return s.accessPolicy
}

func (s *DNSServer) clientAllowed(client string) bool {
	return s.accessPolicySnapshot().Allows(client)
}

func (s *DNSServer) clientRateAllowed(client string) bool {
	s.accessMu.RLock()
	limiter := s.clientLimiter
	s.accessMu.RUnlock()
	return limiter == nil || limiter.Allow(client)
}

func (s *DNSServer) acquireQuerySlot() bool {
	max := s.maxConcurrentQueries.Load()
	for {
		current := s.inFlightQueries.Load()
		if max > 0 && current >= max {
			return false
		}
		if s.inFlightQueries.CompareAndSwap(current, current+1) {
			return true
		}
		max = s.maxConcurrentQueries.Load()
	}
}

func (s *DNSServer) releaseQuerySlot() {
	s.inFlightQueries.Add(-1)
}
