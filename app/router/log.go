package router

import (
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/miekg/dns"
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
func (r *Router) logQueryResp(q qCtx, resp *dnsmsg.Msg, rm RespMeta) {
	e := r.logger.Log()
	if e == nil {
		return
	}
	e.Dict("query", logQuery(q))
	e.Dict("resp", logResp(resp, rm))
	e.Msg("query log")
}

func logQuery(q qCtx) *zerolog.Event {
	e := zerolog.Dict()
	e.Uint32("quid", q.uid)
	b, err := dnsmsg.ToReadable(q.q.Name)
	if err != nil {
		e.Bytes("invalid_name", q.q.Name)
	} else {
		e.Bytes("name", b)
		pool.ReleaseBuf(b)
	}
	e.Uint16("class", uint16(q.q.Class))
	e.Uint16("type", uint16(q.q.Type))
	logNetipAddrPort(e, "remote", q.qMeta.RemoteAddr)
	logNetipAddrPort(e, "local", q.qMeta.LocalAddr)
	logNetipPrefix(e, "ecs", q.qInfo.ECS)
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

// If p is invalid, do nothing.
func logNetipPrefix(e *zerolog.Event, key string, p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 4 "/xxx" bits.
	defer pool.ReleaseBuf(buf)
	b := p.AppendTo(buf[:0])
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

func (r *Router) debugLogMsg(q qCtx, m *dnsmsg.Msg, msg string) {
	e := r.logger.Log()
	if e == nil {
		return
	}
	e.Dict("query", logQuery(q))

	m2, err := dnsmsg2dns(m)
	if err != nil {
		e.Err(err).Msg(msg)
	} else {
		e.Any("msg", m2).Msg(msg)
	}
}

func dnsmsg2dns(m *dnsmsg.Msg) (*dns.Msg, error) {
	b := pool.GetBuf(m.Len())
	_, err := m.Pack(b, false, 0)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(b)

	m2 := new(dns.Msg)
	err = m2.Unpack(b)
	if err != nil {
		return nil, err
	}
	return m2, nil
}
