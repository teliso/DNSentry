package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

func parseDNSCryptUpstream(value string) (stamp string, proto dnscrypt.Proto, err error) {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "sdns+tcp://"):
		stamp = "sdns://" + value[len("sdns+tcp://"):]
		proto = dnscrypt.ProtoTCP
	case strings.HasPrefix(lower, "sdns+udp://"):
		stamp = "sdns://" + value[len("sdns+udp://"):]
		proto = dnscrypt.ProtoUDP
	case strings.HasPrefix(lower, "sdns://"):
		stamp = value
		proto = dnscrypt.ProtoUDP
	default:
		return "", "", errors.New("DNSCrypt upstream must be an sdns://, sdns+udp://, or sdns+tcp:// stamp")
	}
	parsed, parseErr := dnsstamps.NewServerStampFromString(stamp)
	if parseErr != nil {
		return "", "", fmt.Errorf("parse DNSCrypt stamp: %w", parseErr)
	}
	if parsed.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return "", "", errors.New("DNSCrypt upstream stamp has a non-DNSCrypt protocol")
	}
	if parsed.ServerAddrStr == "" || parsed.ProviderName == "" || len(parsed.ServerPk) != dnscrypt.KeySize {
		return "", "", errors.New("DNSCrypt upstream stamp is incomplete")
	}
	if _, _, splitErr := net.SplitHostPort(parsed.ServerAddrStr); splitErr != nil {
		return "", "", fmt.Errorf("DNSCrypt upstream stamp has invalid server address: %w", splitErr)
	}
	return stamp, proto, nil
}

func validateDNSCryptUpstreamStamp(value string) error {
	_, _, err := parseDNSCryptUpstream(value)
	return err
}

func newDNSCryptClientEntry(server *DNSServer, stamp string, proto dnscrypt.Proto) *dnscryptClientEntry {
	return &dnscryptClientEntry{
		server: server,
		stamp:  stamp,
		proto:  proto,
		client: dnscrypt.NewClient(&dnscrypt.ClientConfig{Proto: proto}),
	}
}

func (entry *dnscryptClientEntry) resolverInfo(ctx context.Context) (*dnscrypt.ResolverInfo, error) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.retired {
		return nil, errEncryptedClientClosed
	}
	if entry.info != nil && entry.info.ResolverCert != nil && entry.info.ResolverCert.VerifyDate() {
		return entry.info, nil
	}
	info, err := entry.client.DialContext(ctx, entry.stamp)
	if err != nil {
		return nil, err
	}
	entry.info = info
	return info, nil
}

func (entry *dnscryptClientEntry) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	info, err := entry.resolverInfo(ctx)
	if err != nil {
		return nil, err
	}
	return entry.client.ExchangeContext(ctx, request, info)
}

func (entry *dnscryptClientEntry) close() {
	entry.mu.Lock()
	entry.retired = true
	entry.info = nil
	entry.mu.Unlock()
}

func (s *DNSServer) exchangeDNSCrypt(request *dns.Msg, rawUpstream string) (*dns.Msg, error) {
	stamp, proto, err := parseDNSCryptUpstream(rawUpstream)
	if err != nil {
		return nil, err
	}
	entry, err := s.acquireDNSCryptClient(stamp, proto)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamTimeout())
	defer cancel()
	return entry.exchange(ctx, request)
}
