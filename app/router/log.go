package router

import (
	"net"

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
