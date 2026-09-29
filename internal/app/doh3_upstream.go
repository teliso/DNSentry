package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const doh3UpstreamIdleTimeout = 90 * time.Second

func newDoH3ClientEntry(s *DNSServer, hostname, port string) *doh3ClientEntry {
	timeout := s.upstreamTimeout()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: hostname}
	if s.doh3TLSConfig != nil {
		tlsConfig = s.doh3TLSConfig.Clone()
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = hostname
		}
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	transport := &http3.Transport{
		TLSClientConfig:        tlsConfig,
		QUICConfig:             &quic.Config{MaxIdleTimeout: doh3UpstreamIdleTimeout},
		MaxResponseHeaderBytes: httpMaxHeaderBytes,
		DisableCompression:     true,
		Dial: func(ctx context.Context, _ string, dialTLS *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			targets, err := s.bootstrapTargets(hostname, port)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, target := range targets {
				connection, dialErr := quic.DialAddr(ctx, target, dialTLS, quicConfig)
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return &doh3ClientEntry{client: &http.Client{Transport: transport, Timeout: timeout}, transport: transport}
}

func (s *DNSServer) exchangeDoH3(request *dns.Msg, rawEndpoint string) (*dns.Msg, error) {
	parsed, err := url.Parse(rawEndpoint)
	if err != nil || strings.ToLower(parsed.Scheme) != "h3" || parsed.Host == "" {
		return nil, errors.New("DoH3 upstream must be an h3 URL")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	packet, err := request.Pack()
	if err != nil {
		return nil, err
	}
	endpoint := *parsed
	endpoint.Scheme = "https"
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamTimeout())
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/dns-message")
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	httpRequest.Header.Set("User-Agent", "VigorDNS/0.1")

	entry, err := s.acquireDoH3Client(dohOrigin(parsed, port), parsed.Hostname(), port)
	if err != nil {
		return nil, err
	}
	defer s.releaseDoH3Client(entry)

	response, err := entry.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH3 upstream returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, err
	}
	return message, nil
}
