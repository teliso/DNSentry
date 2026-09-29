package app

import (
	"crypto/tls"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/cache"
	"github.com/teliso/DNSentry/internal/querylog"
	"github.com/teliso/DNSentry/internal/rules"
	"golang.org/x/sync/singleflight"
)

type DNSServer struct {
	configMu             sync.RWMutex
	clientMu             sync.RWMutex
	dohMu                sync.Mutex
	doh3Mu               sync.Mutex
	encryptedMu          sync.Mutex
	dnscryptMu           sync.Mutex
	config               *Config
	generation           uint64
	rules                *rules.Store
	cache                *cache.Cache
	logs                 *querylog.Logger
	client               *dns.Client
	pool                 *UpstreamPool
	fallbackPool         *UpstreamPool
	accessMu             sync.RWMutex
	accessPolicy         *clientAccessPolicy
	clientLimiter        *clientRateLimiter
	inFlightQueries      atomic.Int64
	maxConcurrentQueries atomic.Int64
	refreshInFlight      atomic.Int64
	dohClients           map[string]*dohClientEntry
	doh3Clients          map[string]*doh3ClientEntry
	dohClosed            bool
	doh3Closed           bool
	dotClients           map[string]*dotClientEntry
	doqClients           map[string]*doqClientEntry
	dnscryptClients      map[string]*dnscryptClientEntry
	dnscryptClosed       bool
	encryptedClosed      bool
	refreshing           sync.Map
	inflight             singleflight.Group
	dnssecMu             sync.RWMutex
	dnssec               *DNSSECValidator
	dnssecCacheMu        sync.Mutex
	dnssecCacheOK        map[string]struct{}
	localRecords         atomic.Pointer[localRecordSnapshot]
	routes               atomic.Pointer[routeTable]
	doh3TLSConfig        *tls.Config
}

func (s *DNSServer) configSnapshot() Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	if s.config == nil {
		return Config{}
	}
	return *s.config
}

func (s *DNSServer) configGeneration() uint64 {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.generation
}

func (s *DNSServer) updateConfig(config Config) {
	s.configMu.Lock()
	*s.config = config
	s.generation++
	s.configMu.Unlock()
	s.invalidateDoHClients()
	s.invalidateDoH3Clients()
	s.invalidateDNSCryptClients()
	s.invalidateEncryptedClients()
}

func (s *DNSServer) clearCache() {
	s.configMu.Lock()
	s.generation++
	s.configMu.Unlock()
	s.cache.Clear()
	s.clearDNSSECCacheMarks()
}

func (s *DNSServer) upstreamTimeout() time.Duration {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	return s.client.Timeout
}

func (s *DNSServer) setUpstreamTimeout(timeout time.Duration) {
	s.clientMu.Lock()
	s.client.Timeout = timeout
	s.clientMu.Unlock()
}

func (s *DNSServer) clientSnapshot() dns.Client {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	return *s.client
}

func (s *DNSServer) applyConfig(config Config) error {
	previous := s.configSnapshot()
	dnssecChanged := previous.DNSSECValidate != config.DNSSECValidate || previous.DNSSECAutoUpdate != config.DNSSECAutoUpdate || previous.DNSSECTrustAnchorFile != config.DNSSECTrustAnchorFile || !slices.Equal(previous.DNSSECTrustAnchors, config.DNSSECTrustAnchors)
	localRecordsChanged := !localRecordsEqual(previous.LocalRecords, config.LocalRecords)
	accessChanged := !dnsAccessConfigEqual(previous.Access, config.Access)
	if dnssecChanged {
		// validateConfig has already checked the anchors. Keep the old validator
		// if an unexpected construction error occurs, rather than serving with a
		// partially rebuilt state.
		if err := s.rebuildDNSSECValidator(config); err != nil {
			return err
		}
	}
	s.updateConfig(config)
	s.configureAccess(config.Access)
	s.setLocalRecords(config.LocalRecords)
	s.setUpstreamRoutes(config.UpstreamRoutes)
	if previous.CacheEnabled != config.CacheEnabled || previous.CacheSize != config.CacheSize || previous.CacheTTLMin != config.CacheTTLMin || previous.CacheTTLMax != config.CacheTTLMax || previous.OptimisticCache != config.OptimisticCache || previous.OptimisticAnswerTTL != config.OptimisticAnswerTTL || previous.OptimisticMaxAge != config.OptimisticMaxAge || previous.EnableDNSSEC != config.EnableDNSSEC || dnssecChanged || previous.UpstreamMode != config.UpstreamMode || localRecordsChanged || !upstreamRoutesEqual(previous.UpstreamRoutes, config.UpstreamRoutes) || previous.PrivateReverse != config.PrivateReverse || previous.BlockAAAA != config.BlockAAAA || accessChanged || !slices.Equal(previous.Upstreams, config.Upstreams) || !slices.Equal(previous.FallbackUpstreams, config.FallbackUpstreams) || !slices.Equal(previous.BootstrapDNS, config.BootstrapDNS) {
		s.cache.Clear()
		s.clearDNSSECCacheMarks()
	}
	s.cache.SetEnabled(config.CacheEnabled)
	s.cache.SetMaxBytes(config.CacheSize)
	s.setUpstreamTimeout(upstreamTimeout(config.UpstreamTimeout))
	s.pool.Set(config.Upstreams)
	if s.fallbackPool == nil {
		s.fallbackPool = NewUpstreamPool(config.FallbackUpstreams)
	} else {
		s.fallbackPool.Set(config.FallbackUpstreams)
	}
	return nil
}
func (s *DNSServer) Close() error {
	s.closeDoH3Clients()
	if !s.closeDoHClients() {
		s.closeDNSSECValidator()
		return nil
	}
	s.closeDNSCryptClients()
	s.closeEncryptedClients()
	s.closeDNSSECValidator()
	return nil
}
