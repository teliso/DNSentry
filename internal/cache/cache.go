package cache

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Defaults and the short TTL applied to cached SERVFAIL responses.
const (
	DefaultOptimisticAnswerTTL     uint32 = 30
	DefaultOptimisticMaxAgeSeconds uint32 = 12 * 60 * 60
	ServfailTTL                    uint32 = 5

	// Keep enough room in each shard for ordinary DNS packets. Small caches use
	// one shard so their entire capacity remains usable.
	cacheShardMinBytes = 64 << 10
	maxCacheShards     = 32
)

// entryOverhead approximates what an entry costs besides its packet and key:
// the map slot, the list element and the entry struct. It is counted against
// the cache's size so that "4 MB" is close to what the cache really occupies.
const entryOverhead = 192

// entrySize is the number of bytes an entry is charged.
func entrySize(key string, packet []byte) int { return entryOverhead + len(key) + len(packet) }

type cacheEntry struct {
	key     string
	packet  []byte
	expires time.Time
	version uint64
	ttl     uint32 // TTL the entry was stored with, in seconds
	hits    uint32 // fresh hits since insertion, saturating
}

type cacheShard struct {
	mu          sync.Mutex
	items       map[string]*list.Element // values are *cacheEntry; the list is the LRU order, newest first
	lru         *list.List
	maxBytes    int
	usedBytes   int
	nextVersion uint64
}

type Stats struct {
	Entries        int     `json:"entries"`
	UsedBytes      int     `json:"used_bytes"`
	MaxBytes       int     `json:"max_bytes"`
	Hits           uint64  `json:"hits"`
	Misses         uint64  `json:"misses"`
	StaleHits      uint64  `json:"stale_hits"`
	Evictions      uint64  `json:"evictions"`
	Bypasses       uint64  `json:"bypasses"`
	RefreshSuccess uint64  `json:"refresh_success"`
	RefreshFailure uint64  `json:"refresh_failure"`
	Prefetches     uint64  `json:"prefetches"`
	HitRate        float64 `json:"hit_rate"`
}

// Cache spreads entries across independent LRU shards. Entries never move
// between shards, so each key has a stable lock and eviction domain.
type Cache struct {
	shards      []cacheShard
	lifecycleMu sync.Mutex
	enabled     atomic.Bool
	maxBytes    atomic.Int64
	generation  atomic.Uint64

	hits           atomic.Uint64
	misses         atomic.Uint64
	staleHits      atomic.Uint64
	evictions      atomic.Uint64
	bypasses       atomic.Uint64
	refreshSuccess atomic.Uint64
	refreshFailure atomic.Uint64
	prefetches     atomic.Uint64

	clock atomic.Pointer[func() time.Time]
}

func New(maxBytes int, enabled bool) *Cache {
	if maxBytes < 1 {
		maxBytes = 1
	}

	shardCount := cacheShardCount(maxBytes)
	cache := &Cache{shards: make([]cacheShard, shardCount)}
	cache.maxBytes.Store(int64(maxBytes))
	cache.enabled.Store(enabled)
	for index := range cache.shards {
		cache.shards[index] = cacheShard{
			items:    make(map[string]*list.Element),
			lru:      list.New(),
			maxBytes: shardMaxBytes(maxBytes, shardCount, index),
		}
	}
	return cache
}

func cacheShardCount(maxBytes int) int {
	count := maxBytes / cacheShardMinBytes
	if count < 1 {
		return 1
	}
	if count > maxCacheShards {
		return maxCacheShards
	}
	return count
}

func shardMaxBytes(maxBytes, shardCount, index int) int {
	base := maxBytes / shardCount
	if index < maxBytes%shardCount {
		return base + 1
	}
	return base
}

func (c *Cache) shardFor(key string) *cacheShard {
	return &c.shards[cacheHash(key)%uint64(len(c.shards))]
}

func cacheHash(key string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for index := 0; index < len(key); index++ {
		hash ^= uint64(key[index])
		hash *= prime64
	}
	return hash
}

// Get keeps expired entries for a short stale window when optimistic caching
// is enabled. The caller refreshes a stale entry asynchronously.
// Hit is the result of Lookup.
type Hit struct {
	Message *dns.Msg // nil on a miss
	Stale   bool     // expired but served under the optimistic policy
	// Expiring is set on a fresh entry that has been used before and is in the
	// last fifth of its TTL: a good moment to refresh it in the background so
	// popular names never expire while in use.
	Expiring bool
}

// minPrefetchTTL is the smallest stored TTL (seconds) worth prefetching.
const minPrefetchTTL = 10

// Get is Lookup without the prefetch hint.
func (c *Cache) Get(key string, optimistic bool, optimisticAnswerTTL, optimisticMaxAge uint32) (*dns.Msg, bool) {
	hit := c.Lookup(key, optimistic, optimisticAnswerTTL, optimisticMaxAge)
	return hit.Message, hit.Stale
}

// Lookup returns the cached response for key.
func (c *Cache) Lookup(key string, optimistic bool, optimisticAnswerTTL, optimisticMaxAge uint32) Hit {
	if optimisticMaxAge == 0 {
		optimisticMaxAge = DefaultOptimisticMaxAgeSeconds
	}
	if !c.enabled.Load() {
		c.misses.Add(1)
		return Hit{}
	}

	shard := c.shardFor(key)
	shard.mu.Lock()
	element, ok := shard.items[key]
	if !ok {
		shard.mu.Unlock()
		c.misses.Add(1)
		return Hit{}
	}
	entry := *element.Value.(*cacheEntry) // a copy: its packet is immutable, the rest is read here

	now := c.now()
	stale := !now.Before(entry.expires)
	// Compute the stale boundary from the current policy rather than the
	// value stored with the entry, so runtime policy changes take effect.
	staleUntil := entry.expires.Add(time.Duration(optimisticMaxAge) * time.Second)
	if stale && (!optimistic || !now.Before(staleUntil)) {
		shard.removeLocked(key)
		shard.mu.Unlock()
		c.misses.Add(1)
		return Hit{}
	}
	shard.mu.Unlock()

	// Packet decoding is deliberately outside the shard lock. Cached packets
	// are immutable after insertion, and versioning prevents an unpack failure
	// from removing a newer replacement for this key.
	message := new(dns.Msg)
	if message.Unpack(entry.packet) != nil {
		shard.mu.Lock()
		if current, exists := shard.items[key]; exists && current.Value.(*cacheEntry).version == entry.version {
			shard.removeLocked(key)
		}
		shard.mu.Unlock()
		c.misses.Add(1)
		return Hit{}
	}

	expiring := false
	shard.mu.Lock()
	if element, exists := shard.items[key]; exists && element.Value.(*cacheEntry).version == entry.version {
		current := element.Value.(*cacheEntry)
		shard.lru.MoveToFront(element)
		if !stale {
			expiring = current.hits > 0 && current.ttl >= minPrefetchTTL && current.expires.Sub(now)*5 < time.Duration(current.ttl)*time.Second
			if current.hits < ^uint32(0) {
				current.hits++
			}
		}
	}
	shard.mu.Unlock()

	c.hits.Add(1)
	if stale {
		c.staleHits.Add(1)
		if optimisticAnswerTTL == 0 {
			optimisticAnswerTTL = DefaultOptimisticAnswerTTL
		}
		setTTL(message, optimisticAnswerTTL)
	} else {
		remaining := uint32(entry.expires.Sub(now) / time.Second)
		if remaining == 0 {
			remaining = 1
		}
		setTTL(message, remaining)
	}
	return Hit{Message: message, Stale: stale, Expiring: expiring}
}

func (c *Cache) Set(key string, message *dns.Msg, ttl uint32, _ time.Duration) bool {
	if message == nil || ttl == 0 {
		return false
	}

	// Packing can be comparatively expensive and may allocate, so it must not
	// extend the critical section for other entries in the same shard.
	packet, err := message.Pack()
	if err != nil {
		return false
	}
	if !c.enabled.Load() {
		return false
	}

	generation := c.generation.Load()
	shard := c.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	size := entrySize(key, packet)
	if !c.enabled.Load() || generation != c.generation.Load() || size > shard.maxBytes {
		return false
	}

	shard.removeLocked(key)
	for shard.usedBytes+size > shard.maxBytes && len(shard.items) > 0 {
		oldest := shard.lru.Back()
		if oldest == nil {
			break
		}
		shard.removeLocked(oldest.Value.(*cacheEntry).key)
		c.evictions.Add(1)
	}
	if shard.usedBytes+size > shard.maxBytes {
		return false
	}

	shard.nextVersion++
	shard.items[key] = shard.lru.PushFront(&cacheEntry{
		key:     strings.Clone(key), // do not keep a larger string alive through the key
		packet:  packet,
		expires: c.now().Add(time.Duration(ttl) * time.Second),
		version: shard.nextVersion,
		ttl:     ttl,
	})
	shard.usedBytes += size
	return true
}

func (c *Cache) SetEnabled(enabled bool) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()

	if enabled {
		c.enabled.Store(true)
		return
	}

	// Disabling is linearized before clearing. A Set already in progress either
	// completes before its shard is cleared or sees the disabled state before
	// it can insert an entry.
	c.enabled.Store(false)
	c.generation.Add(1)
	c.clearShards()
}

func (c *Cache) SetMaxBytes(maxBytes int) {
	if maxBytes < 1 {
		maxBytes = 1
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.maxBytes.Store(int64(maxBytes))
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		shard.maxBytes = shardMaxBytes(maxBytes, len(c.shards), index)
		for shard.usedBytes > shard.maxBytes && len(shard.items) > 0 {
			oldest := shard.lru.Back()
			if oldest == nil {
				break
			}
			shard.removeLocked(oldest.Value.(*cacheEntry).key)
			c.evictions.Add(1)
		}
		shard.mu.Unlock()
	}
}

func (s *cacheShard) removeLocked(key string) {
	element, ok := s.items[key]
	if !ok {
		return
	}
	entry := element.Value.(*cacheEntry)
	delete(s.items, key)
	s.lru.Remove(element)
	s.usedBytes -= entrySize(entry.key, entry.packet)
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
}

func (s *cacheShard) clearLocked() {
	s.items = make(map[string]*list.Element)
	s.lru.Init()
	s.usedBytes = 0
}

func (c *Cache) clearShards() {
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		shard.clearLocked()
		shard.mu.Unlock()
	}
}

func (c *Cache) Clear() {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.generation.Add(1)
	c.clearShards()
}

func (c *Cache) Stats() Stats {
	stats := Stats{MaxBytes: int(c.maxBytes.Load())}
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		stats.Entries += shard.lru.Len()
		stats.UsedBytes += shard.usedBytes
		shard.mu.Unlock()
	}
	stats.Hits = c.hits.Load()
	stats.Misses = c.misses.Load()
	stats.StaleHits = c.staleHits.Load()
	stats.Evictions = c.evictions.Load()
	stats.Bypasses = c.bypasses.Load()
	stats.RefreshSuccess = c.refreshSuccess.Load()
	stats.RefreshFailure = c.refreshFailure.Load()
	stats.Prefetches = c.prefetches.Load()
	if total := stats.Hits + stats.Misses; total > 0 {
		stats.HitRate = float64(stats.Hits) / float64(total)
	}
	return stats
}

func (c *Cache) now() time.Time {
	if clock := c.clock.Load(); clock != nil {
		return (*clock)()
	}
	return time.Now()
}

// SetClock replaces the time source; it exists so tests can move time forward.
func (c *Cache) SetClock(now func() time.Time) { c.clock.Store(&now) }

// RecordPrefetch counts a background refresh started ahead of expiry.
func (c *Cache) RecordPrefetch() { c.prefetches.Add(1) }

func (c *Cache) RecordBypass() {
	c.bypasses.Add(1)
}

func (c *Cache) RecordRefresh(success bool) {
	if success {
		c.refreshSuccess.Add(1)
		return
	}
	c.refreshFailure.Add(1)
}

// ClampTTL bounds every record TTL (and SOA minimum) to [min, max]; zero means
// no bound on that side. OPT pseudo-records are left untouched.
func ClampTTL(message *dns.Msg, min, max uint32) {
	visit := func(records []dns.RR) {
		for _, record := range records {
			if _, isOPT := record.(*dns.OPT); isOPT {
				continue
			}
			ttl := record.Header().Ttl
			if min > 0 && ttl < min {
				ttl = min
			}
			if max > 0 && ttl > max {
				ttl = max
			}
			if soa, ok := record.(*dns.SOA); ok {
				if min > 0 && soa.Minttl < min {
					soa.Minttl = min
				}
				if max > 0 && soa.Minttl > max {
					soa.Minttl = max
				}
			}
			record.Header().Ttl = ttl
		}
	}
	visit(message.Answer)
	visit(message.Ns)
	visit(message.Extra)
}

// setTTL forces every record TTL to ttl.
func setTTL(message *dns.Msg, ttl uint32) {
	ClampTTL(message, ttl, ttl)
}
