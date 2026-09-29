package app

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func TestDNSCryptConfigGeneratesAndPersistsKeys(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporaryDirectory := t.TempDir()
	if err := os.Chdir(temporaryDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })

	config := testConfig()
	config.Encryption.DNSCrypt = DNSCryptConfig{
		Enabled:      true,
		Listen:       "127.0.0.1:15443",
		ProviderName: "resolver.example",
	}
	if err := saveConfig(config); err != nil {
		t.Fatal(err)
	}
	if config.Encryption.DNSCrypt.PrivateKey == "" || config.Encryption.DNSCrypt.ResolverSecret == "" {
		t.Fatal("saveConfig did not generate DNSCrypt keys")
	}
	loaded, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !dnsCryptConfigEqual(loaded.Encryption.DNSCrypt, config.Encryption.DNSCrypt) {
		t.Fatalf("DNSCrypt config was not persisted: got %#v want %#v", loaded.Encryption.DNSCrypt, config.Encryption.DNSCrypt)
	}
	if err := validateEncryptionConfig(EncryptionConfig{DNSCrypt: DNSCryptConfig{Enabled: true, Listen: "not-an-address", ProviderName: "resolver.example"}}); err == nil {
		t.Fatal("invalid DNSCrypt listen address was accepted")
	}

	jsonData, err := json.Marshal(config.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	var jsonEncryption EncryptionConfig
	if err := json.Unmarshal(jsonData, &jsonEncryption); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(jsonEncryption, config.Encryption) {
		t.Fatalf("JSON DNSCrypt round trip changed config: %#v", jsonEncryption)
	}
	yamlData, err := yaml.Marshal(config.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	var yamlEncryption EncryptionConfig
	if err := yaml.Unmarshal(yamlData, &yamlEncryption); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(yamlEncryption, config.Encryption) {
		t.Fatalf("YAML DNSCrypt round trip changed config: %#v", yamlEncryption)
	}
}

func TestDNSCryptCertificateAndServiceLifecycle(t *testing.T) {
	server := newSecureTestServer(t)
	service, stamp, _ := startDNSCryptServiceWithRetry(t, server)
	if !service.Status().Running {
		t.Fatal("DNSCrypt service did not enter running state")
	}

	query := new(dns.Msg)
	query.SetQuestion("blocked.example.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	udpClient := dnscrypt.NewClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})
	udpInfo, err := udpClient.DialContext(ctx, stamp)
	if err != nil {
		t.Fatal(err)
	}
	response, err := udpClient.ExchangeContext(ctx, query, udpInfo)
	if err != nil {
		t.Fatalf("DNSCrypt UDP query: %v", err)
	}
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DNSCrypt UDP response rcode: %d", response.Rcode)
	}

	tcpClient := dnscrypt.NewClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoTCP})
	tcpInfo, err := tcpClient.DialContext(ctx, stamp)
	if err != nil {
		t.Fatal(err)
	}
	response, err = tcpClient.ExchangeContext(ctx, query, tcpInfo)
	if err != nil {
		t.Fatalf("DNSCrypt TCP query: %v", err)
	}
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DNSCrypt TCP response rcode: %d", response.Rcode)
	}

	upstreamServer := newSecureTestServer(t)
	upstreamResponse, err := upstreamServer.exchangeDNSCrypt(query, stamp)
	if err != nil {
		t.Fatalf("cached DNSCrypt upstream query: %v", err)
	}
	if upstreamResponse.Rcode != dns.RcodeRefused || len(upstreamServer.dnscryptClients) != 1 {
		t.Fatalf("unexpected cached DNSCrypt upstream result: response=%v clients=%d", upstreamResponse.Rcode, len(upstreamServer.dnscryptClients))
	}
	if _, err := upstreamServer.exchangeDNSCrypt(query, "sdns+tcp://"+strings.TrimPrefix(stamp, "sdns://")); err != nil {
		t.Fatalf("DNSCrypt TCP upstream query: %v", err)
	}
	if len(upstreamServer.dnscryptClients) != 2 {
		t.Fatalf("DNSCrypt UDP/TCP clients were not cached independently: %d", len(upstreamServer.dnscryptClients))
	}

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if service.Status().Running {
		t.Fatal("DNSCrypt service remained running after shutdown")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func freeDNSCryptAddress(t *testing.T) string {
	t.Helper()
	for attempt := 0; attempt < 64; attempt++ {
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		address := tcpListener.Addr().String()
		udpListener, udpErr := net.ListenPacket("udp", address)
		if udpErr == nil {
			_ = udpListener.Close()
			_ = tcpListener.Close()
			return address
		}
		_ = tcpListener.Close()
	}
	t.Fatal("could not reserve a TCP/UDP compatible DNSCrypt test port")
	return ""
}

func TestDNSCryptMultipleListeners(t *testing.T) {
	server := newSecureTestServer(t)
	first := freeDNSCryptAddress(t)
	second := freeDNSCryptAddress(t)
	service, err := NewDNSCryptService(server, DNSCryptConfig{
		Enabled:      true,
		Listens:      []string{first, second},
		ProviderName: "resolver.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if len(service.servers) != 4 {
		t.Fatalf("DNSCrypt server count = %d, want 4", len(service.servers))
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func startDNSCryptServiceWithRetry(t *testing.T, server *DNSServer) (*DNSCryptService, string, string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		address := freeDNSCryptAddress(t)
		service, err := NewDNSCryptService(server, DNSCryptConfig{
			Enabled:             true,
			Listen:              address,
			ProviderName:        "resolver.example",
			CertificateTTLHours: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		stamp, stampErr := service.Stamp()
		if stampErr != nil {
			_ = service.Close()
			t.Fatal(stampErr)
		}
		if stamp == "" {
			_ = service.Close()
			t.Fatal("DNSCrypt stamp is empty")
		}
		if bindErr := service.Bind(); bindErr != nil {
			_ = service.Close()
			lastErr = bindErr
			continue
		}
		if startErr := service.Start(context.Background()); startErr == nil {
			return service, stamp, address
		} else {
			_ = service.Close()
			lastErr = startErr
		}
	}
	t.Fatalf("start DNSCrypt service after retries: %v", lastErr)
	return nil, "", ""
}
