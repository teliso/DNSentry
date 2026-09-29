package app

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultOptimisticAnswerTTL     uint32 = 30
	defaultOptimisticMaxAgeSeconds uint32 = 12 * 60 * 60
	servfailCacheTTL               uint32 = 5

	// Keep enough room in each shard for ordinary DNS packets. Small caches use
	// one shard so their entire capacity remains usable.
	cacheShardMinBytes = 64 << 10
	maxCacheShards     = 32
)

type cacheEntry struct {
	packet  []byte
	expires time.Time
	version uint64
}

type cacheShard struct {
	mu          sync.Mutex
	items       map[string]cacheEntry
	lru         *list.List
	nodes       map[string]*list.Element
	maxBytes    int
	usedBytes   int
	nextVersion uint64
}

type CacheStats struct {
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
	HitRate        float64 `json:"hit_rate"`
}

// DNSCache spreads entries across independent LRU shards. Entries never move
// between shards, so each key has a stable lock and eviction domain.
type DNSCache struct {
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
}

func NewDNSCache(maxBytes int, enabled bool) *DNSCache {
	if maxBytes < 1 {
		maxBytes = 1
	}

	shardCount := cacheShardCount(maxBytes)
	cache := &DNSCache{shards: make([]cacheShard, shardCount)}
	cache.maxBytes.Store(int64(maxBytes))
	cache.enabled.Store(enabled)
	for index := range cache.shards {
		cache.shards[index] = cacheShard{
			items:    make(map[string]cacheEntry),
			lru:      list.New(),
			nodes:    make(map[string]*list.Element),
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

func (c *DNSCache) shardFor(key string) *cacheShard {
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
func (c *DNSCache) Get(key string, optimistic bool, optimisticAnswerTTL, optimisticMaxAge uint32) (*dns.Msg, bool) {
	if optimisticMaxAge == 0 {
		optimisticMaxAge = defaultOptimisticMaxAgeSeconds
	}
	if !c.enabled.Load() {
		c.misses.Add(1)
		return nil, false
	}

	shard := c.shardFor(key)
	shard.mu.Lock()
	entry, ok := shard.items[key]
	if !ok {
		shard.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	now := time.Now()
	stale := !now.Before(entry.expires)
	// Compute the stale boundary from the current policy rather than the
	// value stored with the entry, so runtime policy changes take effect.
	staleUntil := entry.expires.Add(time.Duration(optimisticMaxAge) * time.Second)
	if stale && (!optimistic || !now.Before(staleUntil)) {
		shard.removeLocked(key)
		shard.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	shard.mu.Unlock()

	// Packet decoding is deliberately outside the shard lock. Cached packets
	// are immutable after insertion, and versioning prevents an unpack failure
	// from removing a newer replacement for this key.
	message := new(dns.Msg)
	if message.Unpack(entry.packet) != nil {
		shard.mu.Lock()
		if current, exists := shard.items[key]; exists && current.version == entry.version {
			shard.removeLocked(key)
		}
		shard.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	shard.mu.Lock()
	if current, exists := shard.items[key]; exists && current.version == entry.version {
		shard.touchLocked(key)
	}
	shard.mu.Unlock()

	c.hits.Add(1)
	if stale {
		c.staleHits.Add(1)
		if optimisticAnswerTTL == 0 {
			optimisticAnswerTTL = defaultOptimisticAnswerTTL
		}
		setMessageTTL(message, optimisticAnswerTTL)
	} else {
		remaining := uint32(time.Until(entry.expires) / time.Second)
		if remaining == 0 {
			remaining = 1
		}
		setMessageTTL(message, remaining)
	}
	return message, stale
}

func (c *DNSCache) Set(key string, message *dns.Msg, ttl uint32, _ time.Duration) bool {
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
	if !c.enabled.Load() || generation != c.generation.Load() || len(packet) > shard.maxBytes {
		return false
	}

	shard.removeLocked(key)
	for shard.usedBytes+len(packet) > shard.maxBytes && len(shard.items) > 0 {
		oldest := shard.lru.Back()
		if oldest == nil {
			break
		}
		shard.removeLocked(oldest.Value.(string))
		c.evictions.Add(1)
	}
	if shard.usedBytes+len(packet) > shard.maxBytes {
		return false
	}

	shard.nextVersion++
	shard.items[key] = cacheEntry{
		packet:  packet,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
		version: shard.nextVersion,
	}
	shard.usedBytes += len(packet)
	shard.touchLocked(key)
	return true
}

func (c *DNSCache) SetEnabled(enabled bool) {
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

func (c *DNSCache) SetMaxBytes(maxBytes int) {
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
			shard.removeLocked(oldest.Value.(string))
			c.evictions.Add(1)
		}
		shard.mu.Unlock()
	}
}

func (s *cacheShard) touchLocked(key string) {
	if node, ok := s.nodes[key]; ok {
		s.lru.MoveToFront(node)
		return
	}
	s.nodes[key] = s.lru.PushFront(key)
}

func (s *cacheShard) removeLocked(key string) {
	entry, ok := s.items[key]
	if !ok {
		if node, exists := s.nodes[key]; exists {
			s.lru.Remove(node)
			delete(s.nodes, key)
		}
		return
	}
	delete(s.items, key)
	s.usedBytes -= len(entry.packet)
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
	if node, exists := s.nodes[key]; exists {
		s.lru.Remove(node)
		delete(s.nodes, key)
	}
}

func (s *cacheShard) clearLocked() {
	s.items = make(map[string]cacheEntry)
	s.lru.Init()
	s.nodes = make(map[string]*list.Element)
	s.usedBytes = 0
}

func (c *DNSCache) clearShards() {
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		shard.clearLocked()
		shard.mu.Unlock()
	}
}

func (c *DNSCache) Clear() {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.generation.Add(1)
	c.clearShards()
}

func (c *DNSCache) Stats() CacheStats {
	stats := CacheStats{MaxBytes: int(c.maxBytes.Load())}
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
	if total := stats.Hits + stats.Misses; total > 0 {
		stats.HitRate = float64(stats.Hits) / float64(total)
	}
	return stats
}

func (c *DNSCache) RecordBypass() {
	c.bypasses.Add(1)
}

func (c *DNSCache) RecordRefresh(success bool) {
	if success {
		c.refreshSuccess.Add(1)
		return
	}
	c.refreshFailure.Add(1)
}
