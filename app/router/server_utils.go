package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/pp"
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

var (
	errPP2UnexpectedLocalCmd = errors.New("unexpected pp2 LOCAL command")
	errPP2UnexpectedUnspecTp = errors.New("unexpected pp2 UNSPEC transport protocol")
)

func readIpFromPP2(r io.Reader) (pp.HeaderV2, int, error) {
	h, n, err := pp.ReadV2(r)
	if err != nil {
		return pp.HeaderV2{}, n, err
	}
	if h.Command == pp.LOCAL {
		return pp.HeaderV2{}, n, errPP2UnexpectedLocalCmd
	}
	if h.TransportProtocol == pp.UNSPEC {
		return pp.HeaderV2{}, n, errPP2UnexpectedUnspecTp
	}
	return h, n, nil
}
