package app

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestValidateWebTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := generateSelfSigned(cert, key); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]WebTLSConfig{
		"off":                    {},
		"on, self-signed":        {Enabled: true},
		"on, given files":        {Enabled: true, Certificate: cert, PrivateKey: key},
		"off, files not checked": {Certificate: "/nonexistent.crt", PrivateKey: "/nonexistent.key"},
	} {
		if err := validateWebTLS(config); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, config := range map[string]WebTLSConfig{
		"certificate only": {Enabled: true, Certificate: cert},
		"key only":         {Enabled: true, PrivateKey: key},
		"missing files":    {Enabled: true, Certificate: "/nonexistent.crt", PrivateKey: "/nonexistent.key"},
		"mismatched pair":  {Enabled: true, Certificate: cert, PrivateKey: cert},
	} {
		if err := validateWebTLS(config); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSelfSignedCertificateIsCreatedReusedAndRepaired(t *testing.T) {
	dir := t.TempDir()
	first, err := newWebCertificates(WebTLSConfig{Enabled: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	info := first.Info()
	if !info.Enabled || info.Mode != "self-signed" || len(info.Fingerprint) != 95 || info.NotAfter == "" {
		t.Fatalf("info = %#v", info)
	}
	if stat, err := os.Stat(filepath.Join(dir, "web-tls.key")); err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("private key file: %v %v", stat, err)
	}
	leaf := first.leaf
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("certificate does not cover localhost: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("certificate does not cover 127.0.0.1: %v", err)
	}
	if time.Until(leaf.NotAfter) > selfSignedValidity || time.Until(leaf.NotAfter) < selfSignedValidity-time.Hour*48 {
		t.Errorf("validity ends %s", leaf.NotAfter)
	}

	second, err := newWebCertificates(WebTLSConfig{Enabled: true}, dir)
	if err != nil || second.Info().Fingerprint != info.Fingerprint {
		t.Fatalf("restart must reuse the certificate: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "web-tls.crt"), []byte("damaged"), 0644); err != nil {
		t.Fatal(err)
	}
	third, err := newWebCertificates(WebTLSConfig{Enabled: true}, dir)
	if err != nil || third.Info().Fingerprint == info.Fingerprint {
		t.Fatalf("a damaged certificate must be replaced: %v", err)
	}
}

func TestConsoleServesHTTPSAndReloadsRenewedCertificates(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "given.crt"), filepath.Join(dir, "given.key")
	if err := generateSelfSigned(cert, key); err != nil {
		t.Fatal(err)
	}
	certs, err := newWebCertificates(WebTLSConfig{Enabled: true, Certificate: cert, PrivateKey: key}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if certs.Info().Mode != "custom" {
		t.Fatalf("mode = %q", certs.Info().Mode)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{TLSConfig: certs.tlsConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls="+boolText(r.TLS != nil))
	})}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })

	seen := func() (string, string) {
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 3 * time.Second}
		response, err := client.Get("https://" + listener.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		leaf, _ := x509.ParseCertificate(response.TLS.PeerCertificates[0].Raw)
		return string(body), fingerprint(leaf)
	}
	body, first := seen()
	if body != "tls=true" || first != certs.Info().Fingerprint {
		t.Fatalf("served %q with %s", body, first)
	}

	// Renew the files; the next handshake after the check interval presents the new certificate.
	if err := generateSelfSigned(cert, key); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cert, future, future)
	certs.mu.Lock()
	certs.checked = time.Now().Add(-time.Minute)
	certs.mu.Unlock()
	if _, second := seen(); second == first {
		t.Fatal("the renewed certificate was not picked up")
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestWebTLSSettingsRoundTripAndNeedARestart(t *testing.T) {
	config := testConfig()
	config.WebTLS = WebTLSConfig{Enabled: true}
	data, err := yaml.Marshal(newYAMLConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	var decoded yamlConfig
	if err := yaml.Unmarshal(data, &decoded); err != nil || !decoded.toConfig().WebTLS.Enabled {
		t.Fatalf("round trip: %v", err)
	}
	off := testConfig()
	if !restartRequired(*config, *off) || restartRequired(*off, *off) {
		t.Fatal("changing the console's HTTPS setting must require a restart")
	}
	if err := checkAPIPaths(Config{WebTLS: WebTLSConfig{Certificate: "/etc/ssl/x.crt"}}, Config{}); err == nil {
		t.Fatal("an absolute certificate path was accepted through the API")
	}
}
