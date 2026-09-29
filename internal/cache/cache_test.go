package cache

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func expireEntry(t *testing.T, cache *Cache, key string) {
	t.Helper()
	shard := cache.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.items[key]
	if !ok {
		t.Fatalf("cache entry %q is missing", key)
	}
	entry.expires = time.Now().Add(-time.Second)
	shard.items[key] = entry
}

func TestOptimisticMode(t *testing.T) {
	cache := New(2048, true)
	message := new(dns.Msg)
	message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "cached.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	cache.Set("cached", message, 60, 300*time.Second)
	expireEntry(t, cache, "cached")

	if response, _ := cache.Get("cached", false, 10, 300); response != nil {
		t.Fatal("expired entry should not be returned without optimistic caching")
	}
	cache.Set("cached", message, 60, 300*time.Second)
	expireEntry(t, cache, "cached")
	response, stale := cache.Get("cached", true, 10, 300)
	if response == nil || !stale || response.Answer[0].Header().Ttl != 10 {
		t.Fatalf("expected stale response with TTL 10, got response=%v stale=%v", response != nil, stale)
	}
}

func TestCacheUsesLRU(t *testing.T) {
	message := new(dns.Msg)
	message.Question = []dns.Question{{Name: "cached.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "cached.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	packet, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	cache := New(len(packet)*2, true)
	cache.Set("old", message, 60, time.Minute)
	cache.Set("new", message, 60, time.Minute)
	if response, _ := cache.Get("old", false, 0, 0); response == nil {
		t.Fatal("expected old entry to be present")
	}
	cache.Set("newest", message, 60, time.Minute)
	if response, _ := cache.Get("new", false, 0, 0); response != nil {
		t.Fatal("expected least recently used entry to be evicted")
	}
	stats := cache.Stats()
	if stats.Evictions != 1 || stats.Entries != 2 {
		t.Fatalf("unexpected cache stats: %#v", stats)
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	const (
		workers    = 16
		iterations = 200
	)

	cache := New(1<<20, true)
	if len(cache.shards) < 2 {
		t.Fatal("expected a production-sized cache to use multiple shards")
	}
	message := new(dns.Msg)
	message.Question = []dns.Question{{Name: "concurrent.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "concurrent.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}

	start := make(chan struct{})
	var workersDone sync.WaitGroup
	workersDone.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer workersDone.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				key := fmt.Sprintf("concurrent-%d-%d", worker, iteration%32)
				cache.Set(key, message, 60, time.Minute)
				cache.Get(key, false, 0, 0)
				cache.RecordBypass()
				cache.RecordRefresh(iteration%2 == 0)
				_ = cache.Stats()
			}
		}(worker)
	}

	var maintenanceDone sync.WaitGroup
	maintenanceDone.Add(1)
	go func() {
		defer maintenanceDone.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			if iteration%3 == 0 {
				cache.Clear()
			}
			if iteration%5 == 0 {
				cache.SetEnabled(false)
				cache.SetEnabled(true)
			}
			cache.SetMaxBytes(1 << 20)
		}
	}()

	close(start)
	workersDone.Wait()
	maintenanceDone.Wait()

	stats := cache.Stats()
	if stats.UsedBytes > stats.MaxBytes {
		t.Fatalf("cache exceeded max size: %#v", stats)
	}
	if stats.Bypasses != workers*iterations || stats.RefreshSuccess+stats.RefreshFailure != workers*iterations {
		t.Fatalf("atomic counters lost updates: %#v", stats)
	}
}

func TestLookupFlagsPopularEntriesNearExpiry(t *testing.T) {
	cache := New(1<<16, true)
	var offset time.Duration
	cache.SetClock(func() time.Time { return time.Now().Add(offset) })
	set := func(key string, ttl uint32) {
		message := new(dns.Msg)
		message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: key + ".test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)}}
		cache.Set(key, message, ttl, 0)
	}
	set("hot", 100)

	offset = 90 * time.Second // last tenth, but never hit before
	if hit := cache.Lookup("hot", false, 0, 0); hit.Message == nil || hit.Expiring {
		t.Fatalf("first hit must not trigger a prefetch: %#v", hit)
	}
	if hit := cache.Lookup("hot", false, 0, 0); !hit.Expiring {
		t.Fatalf("a used entry in the last fifth of its TTL should be flagged: %#v", hit)
	}
	offset = 0
	if hit := cache.Lookup("hot", false, 0, 0); hit.Expiring {
		t.Fatal("a fresh entry must not be flagged")
	}

	set("short", 5)
	cache.Lookup("short", false, 0, 0)
	offset = 4 * time.Second
	if hit := cache.Lookup("short", false, 0, 0); hit.Expiring {
		t.Fatal("tiny TTLs are not worth prefetching")
	}
	if message, stale := cache.Get("hot", false, 0, 0); message == nil || stale {
		t.Fatal("Get must keep working")
	}
}
