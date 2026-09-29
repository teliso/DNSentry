package app

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
)

func certificateSourceEmpty(config EncryptionConfig) bool {
	return strings.TrimSpace(config.Certificate) == "" && strings.TrimSpace(config.CertificatePEM) == ""
}

func privateKeySourceEmpty(config EncryptionConfig) bool {
	return strings.TrimSpace(config.PrivateKey) == "" && strings.TrimSpace(config.PrivateKeyPEM) == ""
}

func certificateSource(path, pemContent string) ([]byte, error) {
	if content := strings.TrimSpace(pemContent); content != "" {
		return []byte(pemContent), nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("certificate or private key source is empty")
	}
	return os.ReadFile(path)
}

func loadServerCertificate(config EncryptionConfig) (tls.Certificate, error) {
	if strings.TrimSpace(config.CertificatePEM) == "" && strings.TrimSpace(config.PrivateKeyPEM) == "" {
		return tls.LoadX509KeyPair(strings.TrimSpace(config.Certificate), strings.TrimSpace(config.PrivateKey))
	}
	certificate, err := certificateSource(config.Certificate, config.CertificatePEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate source: %w", err)
	}
	privateKey, err := certificateSource(config.PrivateKey, config.PrivateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read private key source: %w", err)
	}
	return tls.X509KeyPair(certificate, privateKey)
}
