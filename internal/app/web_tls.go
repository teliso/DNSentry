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

// WebTLSConfig turns the console into an HTTPS server. Without a certificate
// and key it uses a self-signed certificate that it creates next to the
// configuration file.
type WebTLSConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	Certificate string `json:"certificate" yaml:"certificate,omitempty"` // path of a PEM certificate chain
	PrivateKey  string `json:"private_key" yaml:"private_key,omitempty"` // path of the PEM private key
}

func (c WebTLSConfig) custom() bool {
	return strings.TrimSpace(c.Certificate) != "" || strings.TrimSpace(c.PrivateKey) != ""
}

// validateWebTLS checks the settings, including that a given certificate and key load.
func validateWebTLS(config WebTLSConfig) error {
	certificate, key := strings.TrimSpace(config.Certificate), strings.TrimSpace(config.PrivateKey)
	if (certificate == "") != (key == "") {
		return errors.New("web tls: certificate and private_key must be given together (or both left empty for a self-signed certificate)")
	}
	if config.Enabled && certificate != "" {
		if _, err := tls.LoadX509KeyPair(certificate, key); err != nil {
			return fmt.Errorf("web tls: cannot load the certificate and key: %w", err)
		}
	}
	return nil
}

// WebTLSInfo describes the certificate the console is serving, for the UI.
type WebTLSInfo struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode,omitempty"`        // "custom" or "self-signed"
	Fingerprint string `json:"fingerprint,omitempty"` // SHA-256 of the certificate, upper-case hex
	NotAfter    string `json:"not_after,omitempty"`
}

const (
	selfSignedValidity = 825 * 24 * time.Hour // the longest Apple platforms accept
	selfSignedRenewal  = 30 * 24 * time.Hour
	certReloadInterval = 10 * time.Second
)

// webCertificates supplies the console's certificate and picks up a renewed
// one without a restart.
type webCertificates struct {
	config  WebTLSConfig
	dir     string
	checked time.Time

	mu         sync.Mutex
	cert       *tls.Certificate
	leaf       *x509.Certificate
	mtimes     [2]time.Time
	selfSigned bool
}

func newWebCertificates(config WebTLSConfig, dir string) (*webCertificates, error) {
	w := &webCertificates{config: config, dir: dir, selfSigned: !config.custom()}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *webCertificates) files() (certPath, keyPath string) {
	if w.selfSigned {
		return filepath.Join(w.dir, "web-tls.crt"), filepath.Join(w.dir, "web-tls.key")
	}
	return strings.TrimSpace(w.config.Certificate), strings.TrimSpace(w.config.PrivateKey)
}

func modTime(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

// load reads the certificate files, creating or renewing the self-signed one.
func (w *webCertificates) load() error {
	certPath, keyPath := w.files()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
			pair.Leaf = leaf
			if !w.selfSigned || time.Until(leaf.NotAfter) > selfSignedRenewal {
				w.store(&pair, leaf, certPath, keyPath)
				return nil
			}
		}
	}
	if !w.selfSigned {
		return fmt.Errorf("web tls: cannot load %s and %s: %w", certPath, keyPath, err)
	}
	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return fmt.Errorf("web tls: cannot create a self-signed certificate: %w", err)
	}
	pair, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	pair.Leaf = leaf
	slog.Info("created a self-signed certificate for the console", "certificate", certPath, "sha256", fingerprint(leaf))
	w.store(&pair, leaf, certPath, keyPath)
	return nil
}

func (w *webCertificates) store(pair *tls.Certificate, leaf *x509.Certificate, certPath, keyPath string) {
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
		if modTime(certPath) != mtimes[0] || modTime(keyPath) != mtimes[1] || (w.selfSigned && time.Until(w.leafNotAfter()) <= selfSignedRenewal) {
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
	mode := "custom"
	if w.selfSigned {
		mode = "self-signed"
	}
	return WebTLSInfo{Enabled: true, Mode: mode, Fingerprint: fingerprint(w.leaf), NotAfter: w.leaf.NotAfter.UTC().Format(time.RFC3339)}
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
// and addresses, plus localhost.
func generateSelfSigned(certPath, keyPath string) error {
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
