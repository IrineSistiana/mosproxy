package router

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

const (
	defaultTCPIdleTimeout = time.Second * 10
	tlsHandshakeTimeout   = time.Second * 3
)

// Note: the returned buffer is not trimmed. It supports to be released asap.
func packResp(m *dnsmsg.Msg, compression bool, size int) (pool.Buffer, error) {
	if size > 65535 {
		size = 65535
	}
	b := pool.GetBuf(m.Len())
	n, err := m.Pack(b, compression, size)
	if err != nil {
		pool.ReleaseBuf(b)
		return nil, err
	}
	b = b[:n]
	return b, nil
}

func packRespTCP(m *dnsmsg.Msg, compression bool) (pool.Buffer, error) {
	b := pool.GetBuf(2 + m.Len())
	n, err := m.Pack(b[2:], compression, 65535)
	if err != nil {
		pool.ReleaseBuf(b)
		return nil, err
	}
	binary.BigEndian.PutUint16(b, uint16(n))
	b = b[:2+n]
	return b, nil
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
