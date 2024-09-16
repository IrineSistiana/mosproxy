package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

const (
	defaultTCPIdleTimeout = time.Second * 10
	tlsHandshakeTimeout   = time.Second * 3
)

func packResp(m *dnsmsg.Msg, size int) (pool.Buffer, error) {
	l, err := m.MaxPackLen()
	if err != nil {
		return nil, err
	}
	b := pool.GetBuf(l)
	defer pool.ReleaseBuf(b)

	payload, err := m.Pack(b[:0], true, size)
	if err != nil {
		return nil, err
	}
	return pool.CopyBuf(payload), nil
}

var errPayloadOverflowed = errors.New("payload size overflowed")

func packRespTCP(m *dnsmsg.Msg) (pool.Buffer, error) {
	l, err := m.MaxPackLen()
	if err != nil {
		return nil, err
	}
	b := pool.GetBuf(2 + l)
	defer pool.ReleaseBuf(b)

	payload, err := m.Pack(b[:2], true, 65535)
	if err != nil {
		return nil, err
	}
	payloadLen := len(payload) - 2
	if payloadLen > 65535 {
		return nil, errPayloadOverflowed
	}
	binary.BigEndian.PutUint16(payload, uint16(payloadLen))
	return pool.CopyBuf(payload), nil
}

// Used by servers for the final step before sending resp payload to client.
// If resp must not be nil.
// If tcp is true, size is ignored.
// If resp failed to pack, an header will be packed.
func serverFinalRespB(req, resp *dnsmsg.Msg, tcp bool, size int) pool.Buffer {

	// Set resp hdr according to q.
	// Also set or remove resp edns0 depending on whether q has edns0 or not.
	postProcessResp := func(udpSize uint16) {
		resp.ID = req.ID
		resp.Response = true
		resp.OpCode = req.OpCode
		resp.RecursionAvailable = true
		resp.RecursionDesired = req.RecursionDesired

		if hasEDNS0(req) {
			addOrReplaceOpt(resp, udpSize)
		} else {
			// remove opt from resp
			rr := dnsmsg.PopEDNS0(resp)
			if rr != nil {
				dnsmsg.ReleaseResource(rr)
			}
		}
	}

	var b pool.Buffer
	var err error
	if tcp {
		postProcessResp(4096)
		b, err = packRespTCP(resp)
	} else {
		postProcessResp(uint16(size))
		b, err = packResp(resp, size)
	}
	if err == nil {
		return b
	}

	mlog.L().Error().Err(err).Msg("internal err: failed to pack dns msg")

	// Failed to pack resp.
	// Try only pack header.
	var body []byte
	if tcp {
		b = pool.GetBuf(2 + 12)
		binary.BigEndian.PutUint16(b[:2], 12)
		body = b[2:]
	} else {
		b = pool.GetBuf(12)
		body = b
	}

	hdr := resp.Header
	hdr.RCode = dnsmsg.RCodeServerFailure
	id, bits := hdr.Pack()
	binary.BigEndian.PutUint16(body[0:], id)
	binary.BigEndian.PutUint16(body[2:], bits)
	return b
}

// return an invalid addr if v is not supported.
func netAddr2NetipAddr(v net.Addr) netip.AddrPort {
	switch v := v.(type) {
	case *net.UDPAddr:
		return v.AddrPort()
	case *net.TCPAddr:
		return v.AddrPort()
	default:
		return netip.AddrPort{}
	}
}

// If addr has @ prefix, listen will listen on a abstract unix socket.
// Otherwise, listen will listen on tcp socket.
func (r *Router) listen(cfg *ServerConfig) (net.Listener, error) {
	controlOpt := cfg.Socket
	controlOpt._TCP_USER_TIMEOUT = 5000 // 5s
	lc := net.ListenConfig{Control: controlSocket(controlOpt)}
	listenerNetwork := "tcp"
	if strings.HasPrefix(cfg.Listen, "@") {
		listenerNetwork = "unix"
	}
	l, err := lc.Listen(r.ctx, listenerNetwork, cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to listen socket, %w", err)
	}
	return l, err
}

type connTracker[T comparable] struct {
	closeConn     func(T)
	closeListener func()

	m      sync.Mutex
	closed bool
	conns  map[T]struct{}
}

// closeListener will only be run once.
func newConnTracker[T comparable](closeConn func(T), closeListener func()) *connTracker[T] {
	return &connTracker[T]{
		closeConn:     closeConn,
		closeListener: closeListener,
		conns:         make(map[T]struct{}),
	}
}

func (ct *connTracker[T]) Add(c T) bool {
	ct.m.Lock()
	defer ct.m.Unlock()
	if ct.closed {
		return false
	}
	ct.conns[c] = struct{}{}
	return true
}

func (ct *connTracker[T]) Del(c T) {
	ct.m.Lock()
	defer ct.m.Unlock()
	delete(ct.conns, c)
}

func (ct *connTracker[T]) Len() int {
	ct.m.Lock()
	defer ct.m.Unlock()
	return len(ct.conns)
}

// mark ct as closed, dose not Close connections.
func (ct *connTracker[T]) Close() {
	ct.m.Lock()
	defer ct.m.Unlock()
	if ct.closed {
		return
	}
	ct.closed = true
	ct.closeListener()
	for c := range ct.conns {
		ct.closeConn(c)
	}
}

func (ct *connTracker[T]) Closed() bool {
	ct.m.Lock()
	defer ct.m.Unlock()
	return ct.closed
}

func (q *QueryCtx) parseQuery(m *dnsmsg.Msg) bool {
	// header
	notImpl := m.Response ||
		!m.RecursionDesired ||
		m.OpCode != dnsmsg.OpCode(0)
	if notImpl {
		return false
	}

	if len(m.Questions) != 1 ||
		len(m.Answers) != 0 ||
		len(m.Authorities) != 0 ||
		len(m.Additionals) > 1 { // edns0
		return false
	}

	q.Question.CopyFrom(m.Questions[0])
	q.ClientECS = findECS(m)
	return true
}

func hasEDNS0(m *dnsmsg.Msg) bool {
	end := len(m.Additionals) - 1
	for i := end; i >= 0; i-- {
		r := m.Additionals[i]
		if r.Hdr().Type == dnsmsg.TypeOPT {
			return true
		}
	}
	return false
}
