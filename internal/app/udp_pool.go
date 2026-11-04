package app

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Plain-DNS upstream queries reuse connected UDP sockets instead of opening a
// new socket for every query, which was a large part of the cost of a cache
// miss. Reuse is deliberately conservative:
//
//   - a socket serves one query at a time, so answers can never be mixed up;
//   - anything waiting in a socket is discarded before it is reused, so a
//     datagram planted while it was idle cannot be taken for an answer;
//   - a socket is dropped after any error, after maxUDPUses queries and after
//     udpIdleTTL without use, so source ports still change regularly;
//   - answers are validated exactly as before (ID, question, …).
const (
	maxUDPUses     = 64
	maxIdleUDP     = 16 // idle sockets kept per upstream
	udpIdleTTL     = 10 * time.Second
	udpPoolMaxIdle = 256 // idle sockets kept in total
)

type pooledUDP struct {
	conn  *dns.Conn
	uses  int
	since time.Time
}

type udpConnPool struct {
	mu    sync.Mutex
	idle  map[string][]*pooledUDP
	total int
}

// get returns an idle socket for upstream, or nil.
func (p *udpConnPool) get(upstream string, now time.Time) *pooledUDP {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked(now)
	list := p.idle[upstream]
	if len(list) == 0 {
		return nil
	}
	conn := list[len(list)-1]
	p.idle[upstream] = list[:len(list)-1]
	p.total--
	return conn
}

// put returns a socket after a successful exchange.
func (p *udpConnPool) put(upstream string, conn *pooledUDP, now time.Time) {
	conn.uses++
	conn.since = now
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn.uses >= maxUDPUses || len(p.idle[upstream]) >= maxIdleUDP || p.total >= udpPoolMaxIdle {
		_ = conn.conn.Close()
		return
	}
	if p.idle == nil {
		p.idle = make(map[string][]*pooledUDP)
	}
	p.idle[upstream] = append(p.idle[upstream], conn)
	p.total++
	p.sweepLocked(now)
}

func (p *udpConnPool) sweepLocked(now time.Time) {
	for upstream, list := range p.idle {
		kept := list[:0]
		for _, conn := range list {
			if now.Sub(conn.since) > udpIdleTTL {
				_ = conn.conn.Close()
				p.total--
				continue
			}
			kept = append(kept, conn)
		}
		if len(kept) == 0 {
			delete(p.idle, upstream)
		} else {
			p.idle[upstream] = kept
		}
	}
}

func (p *udpConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for upstream, list := range p.idle {
		for _, conn := range list {
			_ = conn.conn.Close()
		}
		delete(p.idle, upstream)
	}
	p.total = 0
}

// drain discards datagrams waiting in conn and reports whether it is still usable.
func drain(conn *dns.Conn) bool {
	raw := conn.Conn
	if err := raw.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	buf := make([]byte, 1)
	for i := 0; i < 8; i++ {
		if _, err := raw.Read(buf); err != nil {
			var netErr net.Error
			return errors.As(err, &netErr) && netErr.Timeout()
		}
	}
	return false // something keeps arriving: do not trust this socket
}

// exchangeUDP sends request to upstream over UDP, reusing a socket when it can.
func (s *DNSServer) exchangeUDP(client dns.Client, request *dns.Msg, upstream string) (*dns.Msg, error) {
	now := time.Now()
	conn := s.udpPool.get(upstream, now)
	if conn != nil && !drain(conn.conn) {
		_ = conn.conn.Close()
		conn = nil
	}
	if conn == nil {
		raw, err := client.Dial(upstream)
		if err != nil {
			return nil, err
		}
		conn = &pooledUDP{conn: raw}
	}
	response, _, err := client.ExchangeWithConn(request, conn.conn)
	if err != nil {
		_ = conn.conn.Close()
		return response, err
	}
	s.udpPool.put(upstream, conn, time.Now())
	return response, nil
}
