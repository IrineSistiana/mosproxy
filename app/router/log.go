package router

import (
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

type qLogObj dnsmsg.Question

func (o *qLogObj) MarshalZerologObject(e *zerolog.Event) {
	q := (*dnsmsg.Question)(o)

	b, err := dnsmsg.ToReadable(q.Name)
	if err != nil {
		e.Bytes("invalid_name", q.Name)
	} else {
		e.Bytes("name", b)
		pool.ReleaseBuf(b)
	}
	e.Uint16("class", uint16(q.Class))
	e.Uint16("type", uint16(q.Type))
}

type logConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

func debugLogServerConnAccepted(c logConn, logger *zerolog.Logger) {
	logger.Debug().
		Str("network", c.LocalAddr().Network()).
		Stringer("local", c.LocalAddr()).
		Stringer("remote", c.RemoteAddr()).
		Msg("connection opened")
}

func debugLogServerConnClosed(c logConn, logger *zerolog.Logger, cause error) {
	logger.Debug().
		Str("network", c.LocalAddr().Network()).
		Stringer("local", c.LocalAddr()).
		Stringer("remote", c.RemoteAddr()).
		AnErr("cause", cause).
		Msg("connection closed")
}

// log query info without lvl
func (r *Router) logQueryResp(q *dnsmsg.Question, qm QueryMeta, resp *dnsmsg.Msg, rm RespMeta) {
	e := r.logger.Log()
	if e == nil {
		return
	}
	e.Dict("query", logQuery(q, qm))
	e.Dict("resp", logResp(resp, rm))
	e.Msg("query log")
}

func logQuery(q *dnsmsg.Question, qm QueryMeta) *zerolog.Event {
	e := zerolog.Dict()
	b, err := dnsmsg.ToReadable(q.Name)
	if err != nil {
		e.Bytes("invalid_name", q.Name)
	} else {
		e.Bytes("name", b)
		pool.ReleaseBuf(b)
	}
	e.Uint16("class", uint16(q.Class))
	e.Uint16("type", uint16(q.Type))
	logNetipAddrPort(e, "remote", qm.RemoteAddr)
	logNetipAddrPort(e, "local", qm.LocalAddr)
	return e
}

// If addr is invalid, do nothing.
func logNetipAddrPort(e *zerolog.Event, key string, addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
	defer pool.ReleaseBuf(buf)
	b := addr.AppendTo(buf[:0])
	e.Bytes(key, b)
}

func logResp(r *dnsmsg.Msg, rm RespMeta) *zerolog.Event {
	e := zerolog.Dict()
	e.Int("rule", rm.RuleIdx)
	if rm.Cached {
		e.Bool("cached", true)
	}
	if len(rm.IpMark) > 0 {
		e.Str("ip_mark", rm.IpMark)
	}
	if r != nil {
		e.Uint16("rcode", uint16(r.Header.RCode))
	}
	return e
}
