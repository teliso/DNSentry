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

func validate(config WebTLSConfig, encryption EncryptionConfig) error {
	normalizeWebTLS(&config)
	return validateWebTLS(config, encryption)
}

func TestValidateWebTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := generateSelfSigned(cert, key, ""); err != nil {
		t.Fatal(err)
	}
	withCert := EncryptionConfig{Certificate: cert, PrivateKey: key}
	for name, test := range map[string]struct {
		config     WebTLSConfig
		encryption EncryptionConfig
	}{
		"off":                    {WebTLSConfig{}, EncryptionConfig{}},
		"on, self-signed":        {WebTLSConfig{Enabled: true}, EncryptionConfig{}},
		"on, given files":        {WebTLSConfig{Enabled: true, Certificate: cert, PrivateKey: key}, EncryptionConfig{}},
		"off, files not checked": {WebTLSConfig{Certificate: "/nonexistent.crt", PrivateKey: "/nonexistent.key"}, EncryptionConfig{}},
		"reuse encryption":       {WebTLSConfig{Enabled: true, Source: "encryption"}, withCert},
		"server name":            {WebTLSConfig{Enabled: true, ServerName: "DNS.Example.com."}, EncryptionConfig{}},
	} {
		if err := validate(test.config, test.encryption); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, test := range map[string]struct {
		config     WebTLSConfig
		encryption EncryptionConfig
	}{
		"certificate only":       {WebTLSConfig{Enabled: true, Certificate: cert}, EncryptionConfig{}},
		"key only":               {WebTLSConfig{Enabled: true, PrivateKey: key}, EncryptionConfig{}},
		"missing files":          {WebTLSConfig{Enabled: true, Certificate: "/nonexistent.crt", PrivateKey: "/nonexistent.key"}, EncryptionConfig{}},
		"mismatched pair":        {WebTLSConfig{Enabled: true, Certificate: cert, PrivateKey: cert}, EncryptionConfig{}},
		"custom without files":   {WebTLSConfig{Enabled: true, Source: "custom"}, EncryptionConfig{}},
		"reuse without a cert":   {WebTLSConfig{Enabled: true, Source: "encryption"}, EncryptionConfig{}},
		"reuse with a bad cert":  {WebTLSConfig{Enabled: true, Source: "encryption"}, EncryptionConfig{Certificate: "/nonexistent.crt", PrivateKey: "/nonexistent.key"}},
		"unknown source":         {WebTLSConfig{Enabled: true, Source: "magic"}, EncryptionConfig{}},
		"server name is an IP":   {WebTLSConfig{Enabled: true, ServerName: "192.168.1.2"}, EncryptionConfig{}},
		"server name with space": {WebTLSConfig{Enabled: true, ServerName: "not a name"}, EncryptionConfig{}},
	} {
		if err := validate(test.config, test.encryption); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestWebTLSSourceDefaultsKeepEarlierConfigsWorking(t *testing.T) {
	for config, want := range map[WebTLSConfig]string{
		{Enabled: true}: "auto",
		{Enabled: true, Certificate: "a", PrivateKey: "b"}: "custom",
		{Enabled: true, Source: " Encryption "}:            "encryption",
	} {
		normalizeWebTLS(&config)
		if config.Source != want {
			t.Errorf("source = %q, want %q", config.Source, want)
		}
	}
}

func TestConsoleReusesTheEncryptedDNSCertificateAndBindsAServerName(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "dns.crt"), filepath.Join(dir, "dns.key")
	if err := generateSelfSigned(cert, key, "dns.example.com"); err != nil {
		t.Fatal(err)
	}
	encryption := EncryptionConfig{Certificate: cert, PrivateKey: key}
	reused, err := newWebCertificates(WebTLSConfig{Enabled: true, Source: "encryption", ServerName: "dns.example.com"}, encryption, dir)
	if err != nil {
		t.Fatal(err)
	}
	info := reused.Info()
	if info.Mode != "encryption" || !info.Covered || info.ServerName != "dns.example.com" {
		t.Fatalf("info = %#v", info)
	}
	other, err := newWebCertificates(WebTLSConfig{Enabled: true, Source: "encryption", ServerName: "console.example.com"}, encryption, dir)
	if err != nil {
		t.Fatal(err)
	}
	if info := other.Info(); info.Covered || info.Fingerprint != reused.Info().Fingerprint {
		t.Fatalf("a certificate that does not cover the server name must be flagged, not replaced: %#v", info)
	}

	// The same files pasted as PEM work too.
	certPEM, _ := os.ReadFile(cert)
	keyPEM, _ := os.ReadFile(key)
	pasted, err := newWebCertificates(WebTLSConfig{Enabled: true, Source: "encryption"}, EncryptionConfig{CertificatePEM: string(certPEM), PrivateKeyPEM: string(keyPEM)}, dir)
	if err != nil || pasted.Info().Fingerprint != reused.Info().Fingerprint {
		t.Fatalf("pasted PEM: %v", err)
	}
}

func TestSelfSignedCertificateFollowsTheServerName(t *testing.T) {
	dir := t.TempDir()
	plain, err := newWebCertificates(WebTLSConfig{Enabled: true}, EncryptionConfig{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	named, err := newWebCertificates(WebTLSConfig{Enabled: true, ServerName: "console.home.example"}, EncryptionConfig{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if info := named.Info(); !info.Covered || info.Fingerprint == plain.Info().Fingerprint || named.leaf.VerifyHostname("console.home.example") != nil {
		t.Fatalf("a self-signed certificate must be reissued for a new server name: %#v", info)
	}
	again, err := newWebCertificates(WebTLSConfig{Enabled: true, ServerName: "console.home.example"}, EncryptionConfig{}, dir)
	if err != nil || again.Info().Fingerprint != named.Info().Fingerprint {
		t.Fatalf("an unchanged server name must keep the certificate: %v", err)
	}
}

func TestSelfSignedCertificateIsCreatedReusedAndRepaired(t *testing.T) {
	dir := t.TempDir()
	first, err := newWebCertificates(WebTLSConfig{Enabled: true}, EncryptionConfig{}, dir)
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

	second, err := newWebCertificates(WebTLSConfig{Enabled: true}, EncryptionConfig{}, dir)
	if err != nil || second.Info().Fingerprint != info.Fingerprint {
		t.Fatalf("restart must reuse the certificate: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "web-tls.crt"), []byte("damaged"), 0644); err != nil {
		t.Fatal(err)
	}
	third, err := newWebCertificates(WebTLSConfig{Enabled: true}, EncryptionConfig{}, dir)
	if err != nil || third.Info().Fingerprint == info.Fingerprint {
		t.Fatalf("a damaged certificate must be replaced: %v", err)
	}
}

func TestConsoleServesHTTPSAndReloadsRenewedCertificates(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "given.crt"), filepath.Join(dir, "given.key")
	if err := generateSelfSigned(cert, key, ""); err != nil {
		t.Fatal(err)
	}
	certs, err := newWebCertificates(WebTLSConfig{Enabled: true, Certificate: cert, PrivateKey: key}, EncryptionConfig{}, dir)
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
	if err := generateSelfSigned(cert, key, ""); err != nil {
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
