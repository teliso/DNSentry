package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/teliso/DNSentry/internal/fsutil"
)

// Where the console's certificate comes from.
const (
	webTLSAuto       = "auto"       // a self-signed certificate created next to the configuration file
	webTLSEncryption = "encryption" // the certificate of the encrypted DNS service
	webTLSCustom     = "custom"     // certificate and key files given here
)

// WebTLSConfig turns the console into an HTTPS server.
type WebTLSConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Source is "auto", "encryption" or "custom"; empty means custom when
	// Certificate is set and auto otherwise (the layout of earlier versions).
	Source      string `json:"source" yaml:"source,omitempty"`
	Certificate string `json:"certificate" yaml:"certificate,omitempty"` // custom: path of a PEM certificate chain
	PrivateKey  string `json:"private_key" yaml:"private_key,omitempty"` // custom: path of the PEM private key
	// ServerName is the host name the console is opened with (for example the
	// name of the DoH/DoT certificate). A self-signed certificate is issued for
	// it, and the console warns if the certificate in use does not cover it.
	ServerName string `json:"server_name" yaml:"server_name,omitempty"`
}

// IsZero lets the YAML encoder leave the section out while it holds nothing
// but defaults, so configurations that do not use HTTPS stay uncluttered.
func (c WebTLSConfig) IsZero() bool {
	return !c.Enabled && (c.Source == "" || c.Source == webTLSAuto) && c.Certificate == "" && c.PrivateKey == "" && c.ServerName == ""
}

// normalizeWebTLS fills in Source and tidies ServerName.
func normalizeWebTLS(config *WebTLSConfig) {
	config.Source = strings.ToLower(strings.TrimSpace(config.Source))
	if config.Source == "" {
		config.Source = webTLSAuto
		if strings.TrimSpace(config.Certificate) != "" || strings.TrimSpace(config.PrivateKey) != "" {
			config.Source = webTLSCustom
		}
	}
	config.ServerName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(config.ServerName), "."))
}

// validateWebTLS checks the settings, including that the certificate loads.
// config must have been through normalizeWebTLS.
func validateWebTLS(config WebTLSConfig, encryption EncryptionConfig) error {
	if config.ServerName != "" && (net.ParseIP(config.ServerName) != nil || !validHost(config.ServerName)) {
		return errors.New("web tls: server_name must be a host name such as dns.example.com")
	}
	certificate, key := strings.TrimSpace(config.Certificate), strings.TrimSpace(config.PrivateKey)
	switch config.Source {
	case webTLSAuto:
	case webTLSEncryption:
		if config.Enabled {
			if certificateSourceEmpty(encryption) || privateKeySourceEmpty(encryption) {
				return errors.New("web tls: the encrypted DNS certificate and private key are not configured (Settings → Encrypted DNS)")
			}
			if _, err := loadServerCertificate(encryption); err != nil {
				return fmt.Errorf("web tls: cannot load the encrypted DNS certificate: %w", err)
			}
		}
	case webTLSCustom:
		if (certificate == "") != (key == "") {
			return errors.New("web tls: certificate and private_key must be given together")
		}
		if config.Enabled {
			if certificate == "" {
				return errors.New("web tls: give a certificate and private key, or choose another certificate source")
			}
			if _, err := tls.LoadX509KeyPair(certificate, key); err != nil {
				return fmt.Errorf("web tls: cannot load the certificate and key: %w", err)
			}
		}
	default:
		return errors.New("web tls: source must be auto, encryption or custom")
	}
	return nil
}

// WebTLSInfo describes the certificate the console is serving, for the UI.
type WebTLSInfo struct {
	Enabled     bool     `json:"enabled"`
	Mode        string   `json:"mode,omitempty"`        // "self-signed", "encryption" or "custom"
	Fingerprint string   `json:"fingerprint,omitempty"` // SHA-256 of the certificate, upper-case hex
	NotAfter    string   `json:"not_after,omitempty"`
	Names       []string `json:"names,omitempty"` // host names and addresses the certificate is valid for
	ServerName  string   `json:"server_name,omitempty"`
	// Covered is false when ServerName is set but the certificate does not match it.
	Covered bool `json:"covered"`
}

const (
	selfSignedValidity = 825 * 24 * time.Hour // the longest Apple platforms accept
	selfSignedRenewal  = 30 * 24 * time.Hour
	certReloadInterval = 10 * time.Second
)

// webCertificates supplies the console's certificate and picks up a renewed
// one without a restart.
type webCertificates struct {
	config     WebTLSConfig
	encryption EncryptionConfig // the encrypted DNS settings, for Source "encryption"
	dir        string
	checked    time.Time

	mu     sync.Mutex
	cert   *tls.Certificate
	leaf   *x509.Certificate
	mtimes [2]time.Time
}

func newWebCertificates(config WebTLSConfig, encryption EncryptionConfig, dir string) (*webCertificates, error) {
	normalizeWebTLS(&config)
	w := &webCertificates{config: config, encryption: encryption, dir: dir}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *webCertificates) selfSigned() bool { return w.config.Source == webTLSAuto }

// files lists the certificate files, for change detection. Certificates given
// as pasted PEM have none.
func (w *webCertificates) files() (certPath, keyPath string) {
	switch w.config.Source {
	case webTLSAuto:
		return filepath.Join(w.dir, "web-tls.crt"), filepath.Join(w.dir, "web-tls.key")
	case webTLSEncryption:
		if strings.TrimSpace(w.encryption.CertificatePEM) != "" || strings.TrimSpace(w.encryption.PrivateKeyPEM) != "" {
			return "", ""
		}
		return strings.TrimSpace(w.encryption.Certificate), strings.TrimSpace(w.encryption.PrivateKey)
	default:
		return strings.TrimSpace(w.config.Certificate), strings.TrimSpace(w.config.PrivateKey)
	}
}

func modTime(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

// read loads the configured certificate and key.
func (w *webCertificates) read() (tls.Certificate, error) {
	switch w.config.Source {
	case webTLSEncryption:
		return loadServerCertificate(w.encryption)
	default:
		certPath, keyPath := w.files()
		return tls.LoadX509KeyPair(certPath, keyPath)
	}
}

// load reads the certificate, creating or renewing the self-signed one.
func (w *webCertificates) load() error {
	pair, err := w.read()
	if err == nil {
		if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
			pair.Leaf = leaf
			if !w.selfSigned() || w.selfSignedUsable(leaf) {
				w.store(&pair, leaf)
				return nil
			}
		}
	}
	if !w.selfSigned() {
		return fmt.Errorf("web tls: cannot load the certificate: %w", err)
	}
	certPath, keyPath := w.files()
	if err := generateSelfSigned(certPath, keyPath, w.config.ServerName); err != nil {
		return fmt.Errorf("web tls: cannot create a self-signed certificate: %w", err)
	}
	pair, err = w.read()
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	pair.Leaf = leaf
	slog.Info("created a self-signed certificate for the console", "certificate", certPath, "server_name", w.config.ServerName, "sha256", fingerprint(leaf))
	w.store(&pair, leaf)
	return nil
}

// selfSignedUsable reports whether an existing self-signed certificate can
// stay: not about to expire and valid for the configured server name.
func (w *webCertificates) selfSignedUsable(leaf *x509.Certificate) bool {
	if time.Until(leaf.NotAfter) <= selfSignedRenewal {
		return false
	}
	return w.config.ServerName == "" || leaf.VerifyHostname(w.config.ServerName) == nil
}

func (w *webCertificates) store(pair *tls.Certificate, leaf *x509.Certificate) {
	certPath, keyPath := w.files()
	w.mu.Lock()
	w.cert, w.leaf = pair, leaf
	w.mtimes = [2]time.Time{modTime(certPath), modTime(keyPath)}
	w.checked = time.Now()
	w.mu.Unlock()
}

// get is the tls.Config.GetCertificate hook. It re-reads the files when they
// change (checked at most every few seconds) and keeps the old certificate if
// the new files are unusable.
func (w *webCertificates) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.mu.Lock()
	due := time.Since(w.checked) >= certReloadInterval
	if due {
		w.checked = time.Now()
	}
	current, mtimes := w.cert, w.mtimes
	w.mu.Unlock()
	if due {
		certPath, keyPath := w.files()
		if modTime(certPath) != mtimes[0] || modTime(keyPath) != mtimes[1] || (w.selfSigned() && time.Until(w.leafNotAfter()) <= selfSignedRenewal) {
			if err := w.load(); err != nil {
				slog.Warn("keeping the previous console certificate", "error", err)
			} else {
				w.mu.Lock()
				current = w.cert
				w.mu.Unlock()
			}
		}
	}
	return current, nil
}

func (w *webCertificates) leafNotAfter() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.leaf.NotAfter
}

func (w *webCertificates) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: w.get, NextProtos: []string{"h2", "http/1.1"}}
}

// Info reports what is being served; a nil receiver means HTTPS is off.
func (w *webCertificates) Info() WebTLSInfo {
	if w == nil {
		return WebTLSInfo{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	mode := w.config.Source
	if w.selfSigned() {
		mode = "self-signed"
	}
	names := append([]string(nil), w.leaf.DNSNames...)
	for _, ip := range w.leaf.IPAddresses {
		names = append(names, ip.String())
	}
	info := WebTLSInfo{Enabled: true, Mode: mode, Fingerprint: fingerprint(w.leaf), NotAfter: w.leaf.NotAfter.UTC().Format(time.RFC3339), Names: names, ServerName: w.config.ServerName, Covered: true}
	if w.config.ServerName != "" {
		info.Covered = w.leaf.VerifyHostname(w.config.ServerName) == nil
	}
	return info
}

func fingerprint(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":")
}

// generateSelfSigned writes a certificate that covers this machine's host name
// and addresses, localhost and, if given, serverName.
func generateSelfSigned(certPath, keyPath, serverName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return err
	}
	names := []string{"localhost"}
	if host, err := os.Hostname(); err == nil && host != "" && host != "localhost" {
		names = append(names, host)
	}
	if serverName != "" && serverName != "localhost" {
		names = append([]string{serverName}, names...)
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, address := range addresses {
			if network, ok := address.(*net.IPNet); ok && !network.IP.IsLoopback() && !network.IP.IsLinkLocalUnicast() && !network.IP.IsLinkLocalMulticast() {
				ips = append(ips, network.IP)
			}
		}
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "DNSentry console", Organization: []string{"DNSentry"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	// Key first: a certificate without its key is useless, the reverse is harmless.
	if err := fsutil.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}
