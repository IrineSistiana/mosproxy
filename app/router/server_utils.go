package router

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
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
func (r *router) listen(cfg *ServerConfig) (net.Listener, error) {
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
