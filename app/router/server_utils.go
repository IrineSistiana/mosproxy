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
	pp2HeaderReadTimeout  = time.Second * 2
	defaultTCPIdleTimeout = time.Second * 10
	tlsHandshakeTimeout   = time.Second * 3
)

// Note: the returned buffer is not trimmed. It supports to be released asap.
func packResp(m *dnsmsg.Msg, compression bool, size int) (*pool.Buffer, error) {
	if size > 65535 {
		size = 65535
	}
	b := pool.GetBuf(m.Len())
	n, err := m.Pack(b.B(), compression, size)
	if err != nil {
		pool.ReleaseBuf(b)
		return nil, err
	}
	b.ApplySize(n)
	return b, nil
}

func packRespTCP(m *dnsmsg.Msg, compression bool) (*pool.Buffer, error) {
	buf := pool.GetBuf(2 + m.Len())
	n, err := m.Pack(buf.B()[2:], compression, 65535)
	if err != nil {
		pool.ReleaseBuf(buf)
		return nil, err
	}
	binary.BigEndian.PutUint16(buf.B(), uint16(n))
	buf.ApplySize(2 + n)
	return buf, nil
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

func firstValidAddr(ap netip.AddrPort, netAddr net.Addr) netip.AddrPort {
	if ap.IsValid() {
		return ap
	}
	return netAddr2NetipAddr(netAddr)
}

func firstValidAddrStringer(ap netip.AddrPort, netAddr net.Addr) fmt.Stringer {
	if ap.IsValid() {
		return ap
	}
	return netAddr
}
