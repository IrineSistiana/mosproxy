package router

import (
	"net"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

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

func (r *Router) debugLogMsg(q *QueryCtx, m *dnsmsg.Msg, upstream, msg string) {
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
	e.Str("upstream", upstream)
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
