package router

import (
	"net"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// qid name class type and ecs zone
func (q *QueryCtx) LogQuery() *zerolog.Event {
	e := zerolog.Dict()
	e.Uint32("qid", q.Qid)

	b := pool.GetBuf(1024)
	e.Bytes("name", q.Question.Name.AppendReadableTo(b[:0]))
	pool.ReleaseBuf(b)
	e.Uint16("class", uint16(q.Question.Class))
	e.Uint16("type", uint16(q.Question.Type))
	logNetipPrefix(e, "ecs", q.ECS2Upstream)
	if len(q.ECSZone) > 0 {
		e.Str("ecs_zone", q.ECSZone)
	}
	return e
}

// qid name class type and ecs zone
func (q *QueryCtx) LogServerMeta() *zerolog.Event {
	e := zerolog.Dict()
	if len(q.ServerTag) > 0 {
		e.Str("server", q.ServerTag)
	}
	logNetipAddrPort(e, "remote", q.RemoteAddr)
	if len(q.ServerName) > 0 {
		e.Bytes("sni", q.ServerName)
	}
	if len(q.Host) > 0 {
		e.Bytes("host", q.Host)
	}
	if len(q.Path) > 0 {
		e.Bytes("path", q.Path)
	}
	return e
}

// qid name class type and ecs zone
func (q *QueryCtx) LogResp() *zerolog.Event {
	e := zerolog.Dict()
	if r := q.Resp; r != nil {
		e.Uint16("rcode", uint16(r.RCode))
	}

	e.Int("rule", q.Trace.RuleIdx)
	if q.Trace.Cached {
		e.Bool("cached", true)
	}

	if !q.Start.IsZero() {
		e.Dur("elapsed", time.Since(q.Start))
	}
	return e
}

type logConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

func debugLogServerConnAccepted(c logConn, logger *zerolog.Logger) {
	e := logger.Debug()
	if e != nil {
		e.Str("network", c.LocalAddr().Network()).
			Stringer("local", c.LocalAddr()).
			Stringer("remote", c.RemoteAddr()).
			Msg("connection opened")
	}
}

func debugLogServerConnClosed(c logConn, logger *zerolog.Logger, cause error) {
	e := logger.Debug()
	if e != nil {
		e.Str("network", c.LocalAddr().Network()).
			Stringer("local", c.LocalAddr()).
			Stringer("remote", c.RemoteAddr()).
			AnErr("cause", cause).
			Msg("connection closed")
	}
}

// log query info without lvl
func (r *Router) logAccess(q *QueryCtx) {
	e := r.logger.Log()
	if e == nil {
		return
	}

	e.Dict("query", q.LogQuery())
	e.Dict("meta", q.LogServerMeta())
	e.Dict("resp", q.LogResp())
	e.Msg("query log")
}

// If addr is invalid, do nothing.
func logNetipAddrPort(e *zerolog.Event, key string, addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
	defer pool.ReleaseBuf(buf)
	e.Bytes(key, addr.AppendTo(buf[:0]))
}

// If p is invalid, do nothing.
func logNetipPrefix(e *zerolog.Event, key string, p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 4 "/xxx" bits.
	defer pool.ReleaseBuf(buf)
	e.Bytes(key, p.AppendTo(buf[:0]))
}

func (r *Router) debugLogMsg(q *QueryCtx, m *dnsmsg.Msg, msg string) {
	e := r.logger.Log()
	if e == nil {
		return
	}
	e.Dict("query", q.LogQuery())

	m2, err := dnsmsg2dns(m)
	if err != nil {
		e.Err(err).Msg(msg)
	} else {
		e.Any("msg", m2).Msg(msg)
	}
}

func dnsmsg2dns(m *dnsmsg.Msg) (*dns.Msg, error) {
	l, err := m.MaxPackLen()
	if err != nil {
		return nil, err
	}
	b := pool.GetBuf(l)
	defer pool.ReleaseBuf(b)

	_, err = m.Pack(b[:0], false, 0)
	if err != nil {
		return nil, err
	}

	m2 := new(dns.Msg)
	err = m2.Unpack(b)
	if err != nil {
		return nil, err
	}
	return m2, nil
}
