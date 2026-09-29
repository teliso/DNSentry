package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func upstreamTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		seconds = 4
	}
	return time.Duration(seconds) * time.Second
}

func (s *DNSServer) exchangeUpstream(request *dns.Msg, upstream string) (*dns.Msg, error) {
	lower := strings.ToLower(upstream)
	validationRequest := request
	isDoQ := strings.HasPrefix(lower, "quic://") || strings.HasPrefix(lower, "doq://")
	if isDoQ {
		// RFC 9250 requires the DNS ID in a DoQ query and response to be zero.
		validationRequest = request.Copy()
		validationRequest.Id = 0
	}

	var (
		response *dns.Msg
		err      error
	)
	switch {
	case strings.HasPrefix(lower, "h3://"):
		response, err = s.exchangeDoH3(request, upstream)
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		response, err = s.exchangeDoT(request, upstream)
	case strings.HasPrefix(lower, "https://"):
		response, err = s.exchangeDoH(request, upstream)
	case strings.HasPrefix(lower, "quic://"), strings.HasPrefix(lower, "doq://"):
		response, err = s.exchangeDoQ(request, upstream)
	case strings.HasPrefix(lower, "sdns://"), strings.HasPrefix(lower, "sdns+tcp://"), strings.HasPrefix(lower, "sdns+udp://"):
		response, err = s.exchangeDNSCrypt(request, upstream)
	case isDoQ:
		response, err = s.exchangeDoQ(request, upstream)
	default:
		client := s.clientSnapshot()
		response, _, err = client.Exchange(request, upstream)
		if err == nil && response.Truncated {
			client.Net = "tcp"
			response, _, err = client.Exchange(request, upstream)
		}
	}
	if err != nil {
		return response, err
	}
	if err := validateUpstreamResponse(validationRequest, response); err != nil {
		return nil, err
	}
	return response, nil
}

func validateUpstreamResponse(request, response *dns.Msg) error {
	if request == nil {
		return errors.New("upstream response validation requires a request")
	}
	if response == nil {
		return errors.New("upstream returned an empty response")
	}
	if response.Id != request.Id {
		return fmt.Errorf("upstream response ID %d does not match request ID %d", response.Id, request.Id)
	}
	if !response.Response {
		return errors.New("upstream response is not a response message")
	}
	if response.Opcode != request.Opcode {
		return fmt.Errorf("upstream response opcode %d does not match request opcode %d", response.Opcode, request.Opcode)
	}
	if len(response.Question) != 1 {
		return fmt.Errorf("upstream response has %d questions, want 1", len(response.Question))
	}
	requestQuestion := request.Question
	if len(requestQuestion) != 1 {
		return fmt.Errorf("upstream request has %d questions, want 1", len(requestQuestion))
	}
	responseQuestion := response.Question[0]
	if !strings.EqualFold(dns.Fqdn(responseQuestion.Name), dns.Fqdn(requestQuestion[0].Name)) ||
		responseQuestion.Qtype != requestQuestion[0].Qtype ||
		responseQuestion.Qclass != requestQuestion[0].Qclass {
		return fmt.Errorf("upstream response question does not match request")
	}
	return nil
}

const (
	dohMaxIdleConns        = 100
	dohMaxIdleConnsPerHost = 10
	dohIdleConnTimeout     = 90 * time.Second
	doqMaxMessageSize      = 65535
	doqIdleConnTimeout     = 90 * time.Second
)

var errEncryptedClientClosed = errors.New("encrypted upstream client is closed")

func encryptedOrigin(scheme, hostname, port string) string {
	return scheme + "://" + net.JoinHostPort(strings.ToLower(hostname), port)
}

func newDoTClientEntry(s *DNSServer, hostname, port string) *dotClientEntry {
	timeout := s.upstreamTimeout()
	return &dotClientEntry{
		server:   s,
		hostname: hostname,
		port:     port,
		client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeout,
			Dialer:  &net.Dialer{Timeout: timeout},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: hostname,
			},
		},
	}
}

func (e *dotClientEntry) connection(ctx context.Context) (*dns.Conn, error) {
	e.stateMu.Lock()
	if e.retired {
		e.stateMu.Unlock()
		return nil, errEncryptedClientClosed
	}
	if e.conn != nil {
		conn := e.conn
		e.stateMu.Unlock()
		return conn, nil
	}
	e.stateMu.Unlock()

	targets, err := e.server.bootstrapTargets(e.hostname, e.port)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, target := range targets {
		conn, dialErr := e.client.DialContext(ctx, target)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}

		e.stateMu.Lock()
		if e.retired {
			e.stateMu.Unlock()
			_ = conn.Close()
			return nil, errEncryptedClientClosed
		}
		if e.conn == nil {
			e.conn = conn
			e.stateMu.Unlock()
			return conn, nil
		}
		existing := e.conn
		e.stateMu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	return nil, lastErr
}

func (e *dotClientEntry) discard(conn *dns.Conn) {
	if conn == nil {
		return
	}
	e.stateMu.Lock()
	if e.conn == conn {
		e.conn = nil
	}
	e.stateMu.Unlock()
	_ = conn.Close()
}

func (e *dotClientEntry) close() {
	e.stateMu.Lock()
	e.retired = true
	conn := e.conn
	e.conn = nil
	e.stateMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (e *dotClientEntry) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	// A DNS-over-TCP connection carries one response at a time. Serializing
	// exchanges prevents response framing from being assigned to the wrong request.
	e.exchangeMu.Lock()
	defer e.exchangeMu.Unlock()

	conn, err := e.connection(ctx)
	if err != nil {
		return nil, err
	}
	response, _, err := e.client.ExchangeWithConnContext(ctx, request, conn)
	if err != nil {
		e.discard(conn)
		return nil, err
	}
	return response, nil
}

func newDoQClientEntry(s *DNSServer, hostname, port string) *doqClientEntry {
	return &doqClientEntry{server: s, hostname: hostname, port: port}
}

func (e *doqClientEntry) connection(ctx context.Context) (*quic.Conn, error) {
	e.dialMu.Lock()
	defer e.dialMu.Unlock()

	e.stateMu.Lock()
	if e.retired {
		e.stateMu.Unlock()
		return nil, errEncryptedClientClosed
	}
	if e.conn != nil {
		conn := e.conn
		e.stateMu.Unlock()
		return conn, nil
	}
	e.stateMu.Unlock()

	targets, err := e.server.bootstrapTargets(e.hostname, e.port)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, target := range targets {
		conn, dialErr := quic.DialAddr(ctx, target, &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: e.hostname,
			NextProtos: []string{"doq"},
		}, &quic.Config{MaxIdleTimeout: doqIdleConnTimeout})
		if dialErr != nil {
			lastErr = dialErr
			continue
		}

		e.stateMu.Lock()
		if e.retired {
			e.stateMu.Unlock()
			_ = conn.CloseWithError(0, "client closed")
			return nil, errEncryptedClientClosed
		}
		if e.conn == nil {
			e.conn = conn
			e.stateMu.Unlock()
			return conn, nil
		}
		existing := e.conn
		e.stateMu.Unlock()
		_ = conn.CloseWithError(0, "duplicate connection")
		return existing, nil
	}
	return nil, lastErr
}

func (e *doqClientEntry) discard(conn *quic.Conn) {
	if conn == nil {
		return
	}
	e.stateMu.Lock()
	if e.conn == conn {
		e.conn = nil
	}
	e.stateMu.Unlock()
	_ = conn.CloseWithError(0, "connection failed")
}

func (e *doqClientEntry) close() {
	e.stateMu.Lock()
	e.retired = true
	conn := e.conn
	e.conn = nil
	e.stateMu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "client closed")
	}
}

func (e *doqClientEntry) exchange(ctx context.Context, packet []byte, timeout time.Duration) (*dns.Msg, error) {
	conn, err := e.connection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		e.discard(conn)
		return nil, err
	}
	defer stream.Close()

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if err := stream.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
	if err := writeFull(stream, length[:]); err != nil {
		return nil, err
	}
	if err := writeFull(stream, packet); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return nil, err
	}
	responseLength := int(binary.BigEndian.Uint16(length[:]))
	if responseLength > doqMaxMessageSize {
		return nil, fmt.Errorf("DoQ response is too large: %d bytes", responseLength)
	}
	payload := make([]byte, responseLength)
	if _, err := io.ReadFull(stream, payload); err != nil {
		return nil, err
	}
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, err
	}
	return message, nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func (s *DNSServer) exchangeDoT(request *dns.Msg, rawUpstream string) (*dns.Msg, error) {
	parsed, err := url.Parse(rawUpstream)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid DoT upstream: %s", rawUpstream)
	}
	port := parsed.Port()
	if port == "" {
		port = "853"
	}
	entry, err := s.acquireDoTClient(encryptedOrigin("dot", parsed.Hostname(), port), parsed.Hostname(), port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamTimeout())
	defer cancel()
	return entry.exchange(ctx, request)
}

func dohOrigin(parsed *url.URL, port string) string {
	return strings.ToLower(parsed.Scheme) + "://" + net.JoinHostPort(strings.ToLower(parsed.Hostname()), port)
}

func newDoHClientEntry(s *DNSServer, hostname, port string) *dohClientEntry {
	timeout := s.upstreamTimeout()
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        dohMaxIdleConns,
		MaxIdleConnsPerHost: dohMaxIdleConnsPerHost,
		IdleConnTimeout:     dohIdleConnTimeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			targets, err := s.bootstrapTargets(hostname, port)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, target := range targets {
				connection, dialErr := dialer.DialContext(ctx, network, target)
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return &dohClientEntry{
		client:    &http.Client{Transport: transport, Timeout: timeout},
		transport: transport,
	}
}

func (s *DNSServer) exchangeDoH(request *dns.Msg, endpoint string) (*dns.Msg, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("DoH upstream must be an https URL")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	packet, err := request.Pack()
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/dns-message")
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	httpRequest.Header.Set("User-Agent", "DNSentry/0.1")

	entry, err := s.acquireDoHClient(dohOrigin(parsed, port), parsed.Hostname(), port)
	if err != nil {
		return nil, err
	}
	defer s.releaseDoHClient(entry)

	response, err := entry.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", response.StatusCode)
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

func (s *DNSServer) exchangeDoQ(request *dns.Msg, rawUpstream string) (*dns.Msg, error) {
	parsed, err := url.Parse(rawUpstream)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid DoQ upstream: %s", rawUpstream)
	}
	port := parsed.Port()
	if port == "" {
		port = "853"
	}
	packetMessage := request.Copy()
	packetMessage.Id = 0
	packet, err := packetMessage.Pack()
	if err != nil {
		return nil, err
	}
	if len(packet) > doqMaxMessageSize {
		return nil, errors.New("DNS message is too large for DoQ")
	}
	entry, err := s.acquireDoQClient(encryptedOrigin("doq", parsed.Hostname(), port), parsed.Hostname(), port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamTimeout())
	defer cancel()
	return entry.exchange(ctx, packet, s.upstreamTimeout())
}

func (s *DNSServer) bootstrapTargets(hostname, port string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	config := s.configSnapshot()
	if len(config.BootstrapDNS) == 0 {
		return nil, fmt.Errorf("no bootstrap DNS configured for %s", hostname)
	}
	bootstrapClient := &dns.Client{Net: "udp", Timeout: s.upstreamTimeout()}
	seen := make(map[string]struct{})
	addresses := make([]string, 0, 4)
	for _, bootstrap := range config.BootstrapDNS {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			request := new(dns.Msg)
			request.SetQuestion(dns.Fqdn(hostname), qtype)
			response, _, err := bootstrapClient.Exchange(request, normalizeUpstream(bootstrap))
			if err != nil {
				continue
			}
			for _, answer := range response.Answer {
				var ip net.IP
				switch record := answer.(type) {
				case *dns.A:
					ip = record.A
				case *dns.AAAA:
					ip = record.AAAA
				}
				if ip != nil {
					address := net.JoinHostPort(ip.String(), port)
					if _, exists := seen[address]; !exists {
						seen[address] = struct{}{}
						addresses = append(addresses, address)
					}
				}
			}
		}
		if len(addresses) > 0 {
			break
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("bootstrap DNS could not resolve %s", hostname)
	}
	return addresses, nil
}
