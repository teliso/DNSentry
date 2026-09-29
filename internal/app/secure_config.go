package app

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// EncryptionConfig controls the independent inbound encrypted DNS listeners.
// An empty listener address disables that protocol. The whole service remains
// disabled unless Enabled is true.
type EncryptionConfig struct {
	Enabled        bool           `json:"enabled" yaml:"enabled"`
	Certificate    string         `json:"certificate" yaml:"certificate"`
	PrivateKey     string         `json:"private_key" yaml:"private_key"`
	CertificatePEM string         `json:"certificate_pem,omitempty" yaml:"certificate_pem,omitempty"`
	PrivateKeyPEM  string         `json:"private_key_pem,omitempty" yaml:"private_key_pem,omitempty"`
	DoTListen      string         `json:"dot_listen" yaml:"dot_listen"`
	DoTListens     []string       `json:"dot_listens,omitempty" yaml:"dot_listens,omitempty"`
	DoHListen      string         `json:"doh_listen" yaml:"doh_listen"`
	DoHListens     []string       `json:"doh_listens,omitempty" yaml:"doh_listens,omitempty"`
	DoH3Listen     string         `json:"doh3_listen" yaml:"doh3_listen"`
	DoH3Listens    []string       `json:"doh3_listens,omitempty" yaml:"doh3_listens,omitempty"`
	DoQListen      string         `json:"doq_listen" yaml:"doq_listen"`
	DoQListens     []string       `json:"doq_listens,omitempty" yaml:"doq_listens,omitempty"`
	DNSCrypt       DNSCryptConfig `json:"dnscrypt" yaml:"dnscrypt"`
}

func validateEncryptionConfig(config EncryptionConfig) error {
	if err := validateDNSCryptConfig(config.DNSCrypt); err != nil {
		return err
	}
	if !config.Enabled {
		return nil
	}

	listeners, err := normalizedEncryptionListeners(config)
	if err != nil {
		return err
	}
	hasListener := len(listeners.DoTListens) > 0 || len(listeners.DoHListens) > 0 || len(listeners.DoH3Listens) > 0 || len(listeners.DoQListens) > 0
	if !hasListener && !config.DNSCrypt.Enabled {
		return errors.New("encryption requires at least one listener when enabled")
	}
	if hasListener && (certificateSourceEmpty(config) || privateKeySourceEmpty(config)) {
		return errors.New("encryption certificate and private_key (path or PEM content) are required when an encrypted listener is enabled")
	}
	if hasListener && (strings.TrimSpace(config.CertificatePEM) != "" || strings.TrimSpace(config.PrivateKeyPEM) != "") {
		if _, err := loadServerCertificate(config); err != nil {
			return fmt.Errorf("invalid encryption certificate or private key: %w", err)
		}
	}
	return nil
}

func normalizedEncryptionListeners(config EncryptionConfig) (EncryptionConfig, error) {
	for _, listener := range []struct {
		name   string
		legacy *string
		values *[]string
	}{
		{"DoT listen", &config.DoTListen, &config.DoTListens},
		{"DoH listen", &config.DoHListen, &config.DoHListens},
		{"DoH3 listen", &config.DoH3Listen, &config.DoH3Listens},
		{"DoQ listen", &config.DoQListen, &config.DoQListens},
	} {
		values, err := normalizeListenAddresses(listener.name, *listener.legacy, *listener.values)
		if err != nil {
			return EncryptionConfig{}, err
		}
		*listener.values = values
		*listener.legacy = firstListenAddress(values)
	}
	return config, nil
}

func normalizeEncryptionListeners(config *EncryptionConfig) error {
	if config == nil {
		return errors.New("encryption config is nil")
	}
	normalized, err := normalizedEncryptionListeners(*config)
	if err != nil {
		return err
	}
	*config = normalized
	return nil
}

func encryptionConfigEqual(left, right EncryptionConfig) bool {
	return left.Enabled == right.Enabled &&
		left.Certificate == right.Certificate &&
		left.PrivateKey == right.PrivateKey &&
		left.CertificatePEM == right.CertificatePEM &&
		left.PrivateKeyPEM == right.PrivateKeyPEM &&
		left.DoTListen == right.DoTListen && slices.Equal(left.DoTListens, right.DoTListens) &&
		left.DoHListen == right.DoHListen && slices.Equal(left.DoHListens, right.DoHListens) &&
		left.DoH3Listen == right.DoH3Listen && slices.Equal(left.DoH3Listens, right.DoH3Listens) &&
		left.DoQListen == right.DoQListen && slices.Equal(left.DoQListens, right.DoQListens) &&
		dnsCryptConfigEqual(left.DNSCrypt, right.DNSCrypt)
}

func dnsCryptConfigEqual(left, right DNSCryptConfig) bool {
	return left.Enabled == right.Enabled &&
		left.Listen == right.Listen && slices.Equal(left.Listens, right.Listens) &&
		left.ProviderName == right.ProviderName && left.PrivateKey == right.PrivateKey &&
		left.ResolverSecret == right.ResolverSecret && left.CertificateTTLHours == right.CertificateTTLHours
}

func hasSecureListeners(config EncryptionConfig) bool {
	return len(config.DoTListens) > 0 || len(config.DoHListens) > 0 || len(config.DoH3Listens) > 0 || len(config.DoQListens) > 0
}
