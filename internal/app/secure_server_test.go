package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/vigordns/vigordns/internal/cache"
	"github.com/vigordns/vigordns/internal/querylog"
	"github.com/vigordns/vigordns/internal/rules"
	"gopkg.in/yaml.v3"
)

func newSecureTestServer(t *testing.T) *DNSServer {
	t.Helper()
	directory := t.TempDir()
	ruleFile := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(ruleFile, []byte("||blocked.example^\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules := rules.NewStore(ruleFile)
	if err := rules.Reload(); err != nil {
		t.Fatal(err)
	}
	return &DNSServer{
		config: &Config{
			BlockingMode:       "refused",
			BlockingIPv4:       "0.0.0.0",
			BlockingIPv6:       "::",
			BlockedResponseTTL: 10,
		},
		rules:  rules,
		cache:  cache.New(1<<20, false),
		logs:   querylog.New(10),
		client: &dns.Client{Net: "udp", Timeout: time.Second},
	}
}

func secureTestMessage(t *testing.T, id uint16) []byte {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion("blocked.example.", dns.TypeA)
	message.Id = id
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestEncryptionConfigSerializationIsStable(t *testing.T) {
	original := EncryptionConfig{Enabled: true, Certificate: "cert.pem", PrivateKey: "key.pem", DoTListen: "127.0.0.1:853", DoTListens: []string{"127.0.0.1:853", "127.0.0.1:8853"}, DoHListen: "127.0.0.1:443", DoHListens: []string{"127.0.0.1:443"}, DoH3Listen: "127.0.0.1:8443", DoH3Listens: []string{"127.0.0.1:8443"}, DoQListen: "127.0.0.1:784", DoQListens: []string{"127.0.0.1:784"}}
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
}

func TestSecureDNSListenerNormalizationAndLimit(t *testing.T) {
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{
		Enabled:     true,
		Certificate: "cert.pem",
		PrivateKey:  "key.pem",
		DoTListens:  []string{" 127.0.0.1:8853 ", "127.0.0.1:8853", "127.0.0.1:8854"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.config.DoTListen != "127.0.0.1:8853" || len(service.config.DoTListens) != 2 || service.config.DoTListens[1] != "127.0.0.1:8854" {
		t.Fatalf("unexpected normalized DoT listeners: %#v", service.config)
	}
	tooMany := make([]string, maxConfiguredListens+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("127.0.0.1:%d", 20000+index)
	}
	tooManyConfig := EncryptionConfig{Enabled: true, Certificate: "cert.pem", PrivateKey: "key.pem", DoHListens: tooMany}
	if _, err := NewSecureDNSService(newSecureTestServer(t), tooManyConfig); err == nil {
		t.Fatal("accepted more than the maximum number of DoH listeners")
	}
}

func TestDoHHandlerWireRequestResponse(t *testing.T) {
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	payload := secureTestMessage(t, 0x1234)

	request := httptest.NewRequest(http.MethodPost, "https://dns.example/dns-query", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/dns-message")
	recorder := httptest.NewRecorder()
	service.handleDoH(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("DoH POST status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("DoH content type = %q", got)
	}
	response := new(dns.Msg)
	if err := response.Unpack(recorder.Body.Bytes()); err != nil {
		t.Fatalf("unpack DoH response: %v", err)
	}
	if response.Id != 0x1234 || response.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DoH response: id=%x rcode=%d", response.Id, response.Rcode)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	request = httptest.NewRequest(http.MethodGet, "https://dns.example/dns-query?dns="+encoded, nil)
	recorder = httptest.NewRecorder()
	service.handleDoH(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("DoH GET status = %d", recorder.Code)
	}
	response = new(dns.Msg)
	if err := response.Unpack(recorder.Body.Bytes()); err != nil {
		t.Fatalf("unpack DoH GET response: %v", err)
	}
	if response.Id != 0x1234 || response.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DoH GET response: id=%x rcode=%d", response.Id, response.Rcode)
	}
}

func TestSecureDNSConfigurationValidation(t *testing.T) {
	server := newSecureTestServer(t)
	cases := []EncryptionConfig{
		{Enabled: true, DoHListen: "127.0.0.1:18443"},
		{Enabled: true, Certificate: "cert.pem", PrivateKey: "key.pem", DoTListen: "not-an-address"},
		{Enabled: true, Certificate: "cert.pem", PrivateKey: "key.pem"},
	}
	for _, config := range cases {
		if _, err := NewSecureDNSService(server, config); err == nil {
			t.Fatalf("accepted invalid encryption config: %#v", config)
		}
	}
	service, err := NewSecureDNSService(server, EncryptionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatalf("disabled service should bind without certificate: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSecureDNSDoTLifecycleAndWireFraming(t *testing.T) {
	certificate, privateKey := writeSecureTestCertificate(t)
	address := freeSecureTCPAddress(t)
	config := EncryptionConfig{Enabled: true, Certificate: certificate, PrivateKey: privateKey, DoTListen: address}
	service, err := NewSecureDNSService(newSecureTestServer(t), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &dns.Client{Net: "tcp-tls", Timeout: time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	message := new(dns.Msg)
	message.SetQuestion("blocked.example.", dns.TypeA)
	response, _, err := client.Exchange(message, address)
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if response.Rcode != dns.RcodeRefused || response.Id != message.Id {
		t.Fatalf("unexpected DoT response: id=%x rcode=%d", response.Id, response.Rcode)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		t.Fatal("DoT listener remained open after shutdown")
	}
}

func TestSecureDNSDoQFramingAndLifecycle(t *testing.T) {
	certificate, privateKey := writeSecureTestCertificate(t)
	address := freeSecureUDPAddress(t)
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{Enabled: true, Certificate: certificate, PrivateKey: privateKey, DoQListen: address})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(clientContext, address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatalf("DoQ dial: %v", err)
	}
	stream, err := connection.OpenStreamSync(clientContext)
	if err != nil {
		t.Fatal(err)
	}
	query := secureTestMessage(t, 0)
	var frame [2]byte
	binary.BigEndian.PutUint16(frame[:], uint16(len(query)))
	if err := writeFull(stream, frame[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeFull(stream, query); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, frame[:]); err != nil {
		t.Fatal(err)
	}
	responseLength := binary.BigEndian.Uint16(frame[:])
	responsePayload := make([]byte, responseLength)
	if _, err := io.ReadFull(stream, responsePayload); err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(responsePayload); err != nil {
		t.Fatal(err)
	}
	if response.Id != 0 || response.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected DoQ response: id=%x rcode=%d", response.Id, response.Rcode)
	}
	_ = connection.CloseWithError(0, "test complete")
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
}

func TestSecureDNSServiceBindsAndClosesMultipleDoTAddresses(t *testing.T) {
	certificate, privateKey := writeSecureTestCertificate(t)
	firstAddress := freeSecureTCPAddress(t)
	secondAddress := freeSecureTCPAddress(t)
	service, err := NewSecureDNSService(newSecureTestServer(t), EncryptionConfig{
		Enabled:     true,
		Certificate: certificate,
		PrivateKey:  privateKey,
		DoTListens:  []string{firstAddress, secondAddress},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bind(); err != nil {
		t.Fatal(err)
	}
	if len(service.dotListeners) != 2 || len(service.dotServers) != 2 {
		t.Fatalf("expected two DoT listeners and servers, got listeners=%d servers=%d", len(service.dotListeners), len(service.dotServers))
	}
	if service.dotListener != service.dotListeners[0] || service.dotServer != service.dotServers[0] {
		t.Fatal("legacy DoT fields were not synchronized to the first listener")
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &dns.Client{Net: "tcp-tls", Timeout: time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	for _, address := range []string{firstAddress, secondAddress} {
		message := new(dns.Msg)
		message.SetQuestion("blocked.example.", dns.TypeA)
		response, _, exchangeErr := client.Exchange(message, address)
		if exchangeErr != nil {
			t.Fatalf("DoT exchange on %s: %v", address, exchangeErr)
		}
		if response.Rcode != dns.RcodeRefused {
			t.Fatalf("DoT response on %s has rcode %d, want %d", address, response.Rcode, dns.RcodeRefused)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{firstAddress, secondAddress} {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			t.Fatalf("DoT listener remained bound on %s: %v", address, listenErr)
		}
		_ = listener.Close()
	}
}

func writeSecureTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificate := filepath.Join(directory, "certificate.pem")
	key := filepath.Join(directory, "private-key.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(certificate, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func freeSecureTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func freeSecureUDPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	_ = listener.Close()
	return address
}
