package transport

import (
	"net"

	"github.com/rs/zerolog"
)

type logConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

func debugLogTransportConnOpen(c logConn, logger *zerolog.Logger) {
	logger.Debug().
		Str("network", c.LocalAddr().Network()).
		Stringer("local", c.LocalAddr()).
		Stringer("remote", c.RemoteAddr()).
		Msg("connection opened")
}

func debugLogTransportConnClosed(c logConn, logger *zerolog.Logger, cause error) {
	logger.Debug().
		Str("network", c.LocalAddr().Network()).
		Stringer("local", c.LocalAddr()).
		Stringer("remote", c.RemoteAddr()).
		AnErr("cause", cause).
		Msg("connection closed")
}
