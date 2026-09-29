package app

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureResponseWriter struct {
	response *dns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *captureResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (w *captureResponseWriter) WriteMsg(message *dns.Msg) error {
	w.response = message.Copy()
	return nil
}
func (w *captureResponseWriter) Write(packet []byte) (int, error) {
	message := new(dns.Msg)
	if err := message.Unpack(packet); err != nil {
		return 0, err
	}
	w.response = message
	return len(packet), nil
}
func (w *captureResponseWriter) Close() error        { return nil }
func (w *captureResponseWriter) TsigStatus() error   { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool) {}
func (w *captureResponseWriter) Hijack()             {}

func TestServeDNSCacheLifecycle(t *testing.T) {
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamCount := atomic.Int32{}
	upstream := &dns.Server{PacketConn: upstreamConn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		upstreamCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 42)}}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	defer upstream.Shutdown()

	directory := t.TempDir()
	rulesFile := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(rulesFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules := NewRuleStore(rulesFile)
	if err := rules.Reload(); err != nil {
		t.Fatal(err)
	}
	config := &Config{
		DNSListen: ":15353", HTTPListen: "127.0.0.1:18080", RulesFile: rulesFile,
		Upstreams: []string{upstreamConn.LocalAddr().String()}, CacheEnabled: true, CacheSize: 1 << 20,
		OptimisticAnswerTTL: defaultOptimisticAnswerTTL, OptimisticMaxAge: defaultOptimisticMaxAgeSeconds,
	}
	server := &DNSServer{
		config: config,
		rules:  rules,
		cache:  NewDNSCache(config.CacheSize, true),
		logs:   NewQueryLogger(20),
		client: &dns.Client{Net: "udp", Timeout: time.Second},
		pool:   NewUpstreamPool(config.Upstreams),
	}
	request := newTestRequest("cached.integration.test.", dns.TypeA)

	firstWriter := new(captureResponseWriter)
	server.ServeDNS(firstWriter, request)
	if firstWriter.response == nil || len(firstWriter.response.Answer) != 1 {
		t.Fatalf("first query did not receive an answer: %#v", firstWriter.response)
	}
	secondRequest := request.Copy()
	secondRequest.Id++
	secondWriter := new(captureResponseWriter)
	server.ServeDNS(secondWriter, secondRequest)
	if secondWriter.response == nil || secondWriter.response.Id != secondRequest.Id {
		t.Fatalf("cached query did not preserve request ID: %#v", secondWriter.response)
	}
	if got := upstreamCount.Load(); got != 1 {
		t.Fatalf("expected one upstream query before cache clear, got %d", got)
	}

	server.clearCache()
	thirdWriter := new(captureResponseWriter)
	server.ServeDNS(thirdWriter, request)
	if got := upstreamCount.Load(); got != 2 {
		t.Fatalf("expected cache clear to force a new upstream query, got %d", got)
	}
}

func TestConcurrentIdenticalQueriesAreCoalesced(t *testing.T) {
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()
	upstreamCount := atomic.Int32{}
	upstream := &dns.Server{PacketConn: upstreamConn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		upstreamCount.Add(1)
		time.Sleep(20 * time.Millisecond)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 43)}}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	defer upstream.Shutdown()

	directory := t.TempDir()
	rulesFile := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(rulesFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules := NewRuleStore(rulesFile)
	if err := rules.Reload(); err != nil {
		t.Fatal(err)
	}
	config := &Config{DNSListen: ":15353", HTTPListen: "127.0.0.1:18080", RulesFile: rulesFile, Upstreams: []string{upstreamConn.LocalAddr().String()}, CacheEnabled: true, CacheSize: 1 << 20, OptimisticAnswerTTL: defaultOptimisticAnswerTTL, OptimisticMaxAge: defaultOptimisticMaxAgeSeconds}
	server := &DNSServer{config: config, rules: rules, cache: NewDNSCache(config.CacheSize, true), logs: NewQueryLogger(100), client: &dns.Client{Net: "udp", Timeout: time.Second}, pool: NewUpstreamPool(config.Upstreams)}
	request := newTestRequest("coalesced.integration.test.", dns.TypeA)
	var wait sync.WaitGroup
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			current := request.Copy()
			current.Id = uint16(index + 1)
			writer := new(captureResponseWriter)
			server.ServeDNS(writer, current)
			if writer.response == nil || len(writer.response.Answer) != 1 {
				t.Errorf("concurrent query %d did not receive an answer", index)
			}
		}(index)
	}
	wait.Wait()
	if got := upstreamCount.Load(); got != 1 {
		t.Fatalf("expected identical concurrent queries to share one upstream request, got %d", got)
	}
}
