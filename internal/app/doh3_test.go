package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"gopkg.in/yaml.v3"
)

func TestLoadServerCertificateFromPEM(t *testing.T) {
	certificatePath, privateKeyPath := writeSecureTestCertificate(t)
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	config := EncryptionConfig{
		Enabled:        true,
		DoHListen:      "127.0.0.1:18443",
		CertificatePEM: string(certificatePEM),
		PrivateKeyPEM:  string(privateKeyPEM),
	}
	if err := validateEncryptionConfig(config); err != nil {
		t.Fatalf("valid PEM configuration rejected: %v", err)
	}
	if _, err := loadServerCertificate(config); err != nil {
		t.Fatalf("load certificate from PEM: %v", err)
	}
}

func TestDoH3EncryptionConfigSerializationAndValidation(t *testing.T) {
	original := EncryptionConfig{
		Enabled:     true,
		Certificate: "cert.pem",
		PrivateKey:  "key.pem",
		DoH3Listen:  "127.0.0.1:8443",
	}
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON EncryptionConfig
	if err := json.Unmarshal(jsonData, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromJSON, original) {
		t.Fatalf("JSON round trip changed encryption config: %#v", fromJSON)
	}
	yamlData, err := yaml.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var fromYAML EncryptionConfig
	if err := yaml.Unmarshal(yamlData, &fromYAML); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromYAML, original) {
		t.Fatalf("YAML round trip changed encryption config: %#v", fromYAML)
	}
	if err := validateEncryptionConfig(original); err != nil {
		t.Fatalf("valid DoH3 configuration rejected: %v", err)
	}
	invalid := original
	invalid.DoH3Listen = "not-an-address"
	if err := validateEncryptionConfig(invalid); err == nil {
		t.Fatal("invalid DoH3 listen address was accepted")
	}
}

func TestDoH3HandlerAndLifecycle(t *testing.T) {
	certificate, privateKey := writeSecureTestCertificate(t)
	address := freeSecureUDPAddress(t)
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{
		Enabled:     true,
		Certificate: certificate,
		PrivateKey:  privateKey,
		DoH3Listen:  address,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if service.doh3Listener == nil || service.doh3Server == nil {
		t.Fatal("DoH3 listener and server were not bound")
	}
	if got := service.doh3Server.TLSConfig.MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("DoH3 minimum TLS version = %d, want TLS 1.3", got)
	}
	if len(service.doh3Server.TLSConfig.NextProtos) != 1 || service.doh3Server.TLSConfig.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("DoH3 ALPN = %v, want [%q]", service.doh3Server.TLSConfig.NextProtos, http3.NextProtoH3)
	}
	if service.doh3Server.MaxHeaderBytes != httpMaxHeaderBytes || service.doh3Server.IdleTimeout != secureDoH3IdleTimeout {
		t.Fatalf("DoH3 HTTP limits are not configured: %#v", service.doh3Server)
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}}
	defer transport.Close()
	client := &http.Client{Transport: transport}
	payload := secureTestMessage(t, 0x4321)
	requestContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "https://"+address+"/dns-query", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("DoH3 request: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("unexpected DoH3 response: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	message := unpackSecureTestMessage(t, responsePayload)
	if message.Id != 0x4321 || message.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DoH3 DNS response: id=%x rcode=%d", message.Id, message.Rcode)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		listener, listenErr := net.ListenPacket("udp", address)
		if listenErr == nil {
			_ = listener.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("DoH3 UDP listener remained bound after shutdown: %v", listenErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDoH3UpstreamExchangeAndPooling(t *testing.T) {
	certificate, privateKey := writeSecureTestCertificate(t)
	address := freeSecureUDPAddress(t)
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{
		Enabled:     true,
		Certificate: certificate,
		PrivateKey:  privateKey,
		DoH3Listen:  address,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = service.Shutdown(shutdownContext)
	})

	resolver := &DNSServer{
		config: &Config{},
		client: &dns.Client{Net: "udp", Timeout: time.Second},
		doh3TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
	}
	defer resolver.Close()
	endpoint := "h3://" + address + "/dns-query"
	for _, id := range []uint16{0x4455, 0x4456} {
		request := new(dns.Msg)
		request.SetQuestion("blocked.example.", dns.TypeA)
		request.Id = id
		response, exchangeErr := resolver.exchangeUpstream(request, endpoint)
		if exchangeErr != nil {
			t.Fatalf("exchange DoH3 upstream: %v", exchangeErr)
		}
		if response.Id != id || response.Rcode != dns.RcodeRefused {
			t.Fatalf("unexpected DoH3 upstream response: id=%x rcode=%d", response.Id, response.Rcode)
		}
	}
	resolver.doh3Mu.Lock()
	clientCount := len(resolver.doh3Clients)
	resolver.doh3Mu.Unlock()
	if clientCount != 1 {
		t.Fatalf("DoH3 upstream client pool size = %d, want 1", clientCount)
	}
}

func unpackSecureTestMessage(t *testing.T, payload []byte) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	return message
}
