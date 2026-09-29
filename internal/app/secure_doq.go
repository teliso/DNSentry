package app

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func (s *SecureDNSService) serveDoQ(ctx context.Context, listener *quic.Listener) {
	defer s.wg.Done()
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.state != secureServiceRunning {
			s.mu.Unlock()
			_ = connection.CloseWithError(0, "server is stopping")
			continue
		}
		s.doqConns[connection] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveDoQConnection(ctx, connection)
	}
}

func (s *SecureDNSService) serveDoQConnection(ctx context.Context, connection *quic.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.doqConns, connection)
		s.mu.Unlock()
		_ = connection.CloseWithError(0, "connection complete")
	}()

	var streams sync.WaitGroup
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			streams.Wait()
			return
		}
		streams.Add(1)
		go func(stream *quic.Stream) {
			defer streams.Done()
			s.serveDoQStream(stream, connection)
		}(stream)
	}
}

func (s *SecureDNSService) serveDoQStream(stream *quic.Stream, connection *quic.Conn) {
	defer stream.Close()
	deadline := time.Now().Add(secureStreamTimeout)
	if err := stream.SetReadDeadline(deadline); err != nil {
		return
	}
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return
	}
	messageLength := int(length[0])<<8 | int(length[1])
	if messageLength == 0 || messageLength > secureDNSMaxMessageSize {
		return
	}
	payload := make([]byte, messageLength)
	if _, err := io.ReadFull(stream, payload); err != nil {
		return
	}
	request := new(dns.Msg)
	if err := request.Unpack(payload); err != nil || request.Id != 0 {
		return
	}

	writer := &secureWireResponseWriter{
		local:  connection.LocalAddr(),
		remote: connection.RemoteAddr(),
		write: func(response []byte) error {
			if len(response) == 0 || len(response) > secureDNSMaxMessageSize {
				return fmt.Errorf("DNS response length %d is outside DoQ limits", len(response))
			}
			var frame [2]byte
			frame[0] = byte(len(response) >> 8)
			frame[1] = byte(len(response))
			if err := stream.SetWriteDeadline(time.Now().Add(secureStreamTimeout)); err != nil {
				return err
			}
			if err := writeFull(stream, frame[:]); err != nil {
				return err
			}
			return writeFull(stream, response)
		},
	}
	s.server.ServeDNS(writer, request)
}
