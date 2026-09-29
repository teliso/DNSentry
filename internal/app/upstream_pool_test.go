package app

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newEncryptedPoolTestServer() *DNSServer {
	return &DNSServer{
		config: &Config{},
		client: &dns.Client{Timeout: time.Second},
	}
}

func TestEncryptedEndpointPoolsReuseConcurrently(t *testing.T) {
	server := newEncryptedPoolTestServer()
	const workers = 64

	dotResults := make(chan *dotClientEntry, workers)
	doqResults := make(chan *doqClientEntry, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			dot, err := server.acquireDoTClient("dot://dns.example:853", "dns.example", "853")
			if err != nil {
				t.Errorf("acquire DoT client: %v", err)
				return
			}
			dotResults <- dot
			doq, err := server.acquireDoQClient("doq://dns.example:853", "dns.example", "853")
			if err != nil {
				t.Errorf("acquire DoQ client: %v", err)
				return
			}
			doqResults <- doq
		}()
	}
	close(start)
	wait.Wait()
	close(dotResults)
	close(doqResults)

	var dotFirst *dotClientEntry
	for dot := range dotResults {
		if dotFirst == nil {
			dotFirst = dot
		} else if dot != dotFirst {
			t.Fatal("concurrent DoT acquisition created multiple endpoint entries")
		}
	}
	var doqFirst *doqClientEntry
	for doq := range doqResults {
		if doqFirst == nil {
			doqFirst = doq
		} else if doq != doqFirst {
			t.Fatal("concurrent DoQ acquisition created multiple endpoint entries")
		}
	}

	server.encryptedMu.Lock()
	dotCount, doqCount := len(server.dotClients), len(server.doqClients)
	server.encryptedMu.Unlock()
	if dotCount != 1 || doqCount != 1 {
		t.Fatalf("unexpected encrypted pool sizes: DoT=%d DoQ=%d", dotCount, doqCount)
	}
}

func TestEncryptedEndpointPoolsConcurrentConfigUpdate(t *testing.T) {
	server := newEncryptedPoolTestServer()
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for attempt := 0; attempt < 100; attempt++ {
				if _, err := server.acquireDoTClient("dot://dns.example:853", "dns.example", "853"); err != nil {
					t.Errorf("acquire DoT client during update: %v", err)
				}
				if _, err := server.acquireDoQClient("doq://dns.example:853", "dns.example", "853"); err != nil {
					t.Errorf("acquire DoQ client during update: %v", err)
				}
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for attempt := 0; attempt < 100; attempt++ {
			server.updateConfig(Config{})
		}
	}()
	close(start)
	wait.Wait()
}

func TestEncryptedEndpointPoolsRetireOnConfigUpdate(t *testing.T) {
	server := newEncryptedPoolTestServer()
	dot, err := server.acquireDoTClient("dot://dns.example:853", "dns.example", "853")
	if err != nil {
		t.Fatal(err)
	}
	doq, err := server.acquireDoQClient("doq://dns.example:853", "dns.example", "853")
	if err != nil {
		t.Fatal(err)
	}

	left, right := net.Pipe()
	defer right.Close()
	dot.stateMu.Lock()
	dot.conn = &dns.Conn{Conn: left}
	dot.stateMu.Unlock()

	server.updateConfig(Config{})

	server.encryptedMu.Lock()
	dotCount, doqCount := len(server.dotClients), len(server.doqClients)
	server.encryptedMu.Unlock()
	if dotCount != 0 || doqCount != 0 {
		t.Fatalf("config update left encrypted entries cached: DoT=%d DoQ=%d", dotCount, doqCount)
	}
	dot.stateMu.Lock()
	dotRetired, dotConn := dot.retired, dot.conn
	dot.stateMu.Unlock()
	if !dotRetired || dotConn != nil {
		t.Fatalf("DoT entry was not fully retired: retired=%v conn=%v", dotRetired, dotConn)
	}
	doq.stateMu.Lock()
	doqRetired, doqConn := doq.retired, doq.conn
	doq.stateMu.Unlock()
	if !doqRetired || doqConn != nil {
		t.Fatalf("DoQ entry was not fully retired: retired=%v conn=%v", doqRetired, doqConn)
	}

	right.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected configuration update to close the DoT connection")
	}
}

func TestEncryptedEndpointPoolsClose(t *testing.T) {
	server := newEncryptedPoolTestServer()
	if _, err := server.acquireDoTClient("dot://dns.example:853", "dns.example", "853"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.acquireDoQClient("doq://dns.example:853", "dns.example", "853"); err != nil {
		t.Fatal(err)
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}

	server.encryptedMu.Lock()
	dotCount, doqCount := len(server.dotClients), len(server.doqClients)
	server.encryptedMu.Unlock()
	if dotCount != 0 || doqCount != 0 {
		t.Fatalf("Close left encrypted entries cached: DoT=%d DoQ=%d", dotCount, doqCount)
	}
	if _, err := server.acquireDoTClient("dot://dns.example:853", "dns.example", "853"); err == nil {
		t.Fatal("expected DoT acquisition after Close to fail")
	}
	if _, err := server.acquireDoQClient("doq://dns.example:853", "dns.example", "853"); err == nil {
		t.Fatal("expected DoQ acquisition after Close to fail")
	}
}

func TestUpstreamPoolMarksFailedServers(t *testing.T) {
	pool := NewUpstreamPool([]string{"one:53", "two:53"})
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
	pool := NewUpstreamPool([]string{"one:53"})
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
