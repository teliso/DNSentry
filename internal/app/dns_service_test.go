package app

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSServiceBindsAndClosesMultipleAddresses(t *testing.T) {
	firstAddress := freeDNSCryptAddress(t)
	secondAddress := freeDNSCryptAddress(t)
	service, err := NewDNSService(newSecureTestServer(t), Config{DNSListens: []string{firstAddress, secondAddress}})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if len(service.listeners) != 2 || len(service.Addresses()) != 2 {
		t.Fatalf("expected two DNS listener pairs, got listeners=%d addresses=%d", len(service.listeners), len(service.Addresses()))
	}
	if service.Ready() != true {
		t.Fatal("bound DNS service should be ready")
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	for _, address := range []string{firstAddress, secondAddress} {
		message := new(dns.Msg)
		message.SetQuestion("blocked.example.", dns.TypeA)
		response, _, exchangeErr := client.Exchange(message, address)
		if exchangeErr != nil {
			t.Fatalf("DNS exchange on %s: %v", address, exchangeErr)
		}
		if response.Rcode != dns.RcodeRefused {
			t.Fatalf("DNS response on %s has rcode %d, want %d", address, response.Rcode, dns.RcodeRefused)
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if service.Ready() {
		t.Fatal("closed DNS service should not be ready")
	}
	for _, address := range []string{firstAddress, secondAddress} {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			t.Fatalf("DNS TCP listener remained bound on %s: %v", address, listenErr)
		}
		_ = listener.Close()
		packetConn, packetErr := net.ListenPacket("udp", address)
		if packetErr != nil {
			t.Fatalf("DNS UDP listener remained bound on %s: %v", address, packetErr)
		}
		_ = packetConn.Close()
	}
}

func TestDNSServiceRollsBackAllListenersOnBindFailure(t *testing.T) {
	firstAddress := freeDNSCryptAddress(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	service, err := NewDNSService(newSecureTestServer(t), Config{DNSListens: []string{firstAddress, occupied.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err == nil {
		t.Fatal("DNS service accepted a partially unavailable listener set")
	}
	if len(service.listeners) != 0 {
		t.Fatalf("failed DNS bind retained %d listener pairs", len(service.listeners))
	}
	listener, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("DNS TCP listener was not rolled back: %v", err)
	}
	_ = listener.Close()
	packetConn, err := net.ListenPacket("udp", firstAddress)
	if err != nil {
		t.Fatalf("DNS UDP listener was not rolled back: %v", err)
	}
	_ = packetConn.Close()
}
