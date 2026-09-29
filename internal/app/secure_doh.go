package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

func (s *SecureDNSService) doHHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)
	return mux
}

func (s *SecureDNSService) handleDoH(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		writer.Header().Set("Allow", "GET, POST")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload []byte
	var err error
	if request.Method == http.MethodPost {
		contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(request.Header.Get("Content-Type"), ";", 2)[0]))
		if contentType != "application/dns-message" {
			http.Error(writer, "content type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		if request.ContentLength > secureDNSMaxMessageSize {
			http.Error(writer, "DNS message is too large", http.StatusRequestEntityTooLarge)
			return
		}
		limited := io.LimitReader(request.Body, secureDNSMaxMessageSize+1)
		payload, err = io.ReadAll(limited)
	} else {
		encoded := request.URL.Query().Get("dns")
		if encoded == "" {
			http.Error(writer, "missing dns query parameter", http.StatusBadRequest)
			return
		}
		payload, err = decodeBase64URL(encoded)
	}
	if err != nil {
		http.Error(writer, "invalid DNS message", http.StatusBadRequest)
		return
	}
	if len(payload) == 0 || len(payload) > secureDNSMaxMessageSize {
		http.Error(writer, "DNS message is too large or empty", http.StatusBadRequest)
		return
	}
	requestMessage := new(dns.Msg)
	if err := requestMessage.Unpack(payload); err != nil {
		http.Error(writer, "invalid DNS message", http.StatusBadRequest)
		return
	}

	writer.Header().Set("Content-Type", "application/dns-message")
	writer.Header().Set("Cache-Control", "no-store")
	responseWriter := &secureWireResponseWriter{
		local:  nil,
		remote: secureAddr(request.RemoteAddr),
		write: func(response []byte) error {
			if len(response) == 0 || len(response) > secureDNSMaxMessageSize {
				return fmt.Errorf("DNS response length %d is outside DoH limits", len(response))
			}
			_, err := writer.Write(response)
			return err
		},
	}
	s.server.ServeDNS(responseWriter, requestMessage)
	if !responseWriter.written {
		writer.WriteHeader(http.StatusBadGateway)
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return payload, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

type secureAddr string

func (address secureAddr) Network() string { return "tcp" }
func (address secureAddr) String() string  { return string(address) }

type secureWireResponseWriter struct {
	local   net.Addr
	remote  net.Addr
	write   func([]byte) error
	written bool
}

func (w *secureWireResponseWriter) LocalAddr() net.Addr  { return w.local }
func (w *secureWireResponseWriter) RemoteAddr() net.Addr { return w.remote }

func (w *secureWireResponseWriter) WriteMsg(message *dns.Msg) error {
	payload, err := message.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func (w *secureWireResponseWriter) Write(payload []byte) (int, error) {
	if w.written {
		return 0, errors.New("DNS response already written")
	}
	if err := w.write(payload); err != nil {
		return 0, err
	}
	w.written = true
	return len(payload), nil
}

func (w *secureWireResponseWriter) TsigStatus() error   { return nil }
func (w *secureWireResponseWriter) TsigTimersOnly(bool) {}
func (w *secureWireResponseWriter) Hijack()             {}
func (w *secureWireResponseWriter) Close() error        { return nil }
