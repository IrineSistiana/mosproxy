package transport

import (
	"net"

	"go.uber.org/zap"
)

type logConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

func debugLogTransportNewConn(c logConn, logger *zap.Logger) {
	logger.Check(zap.DebugLevel, "new conn").Write(
		zap.String("network", c.LocalAddr().Network()),
		zap.Stringer("local", c.LocalAddr()),
		zap.Stringer("remote", c.RemoteAddr()),
	)
}

func debugLogTransportConnClosed(c logConn, logger *zap.Logger, cause error) {
	logger.Check(zap.DebugLevel, "conn closed").Write(
		zap.String("network", c.LocalAddr().Network()),
		zap.Stringer("local", c.LocalAddr()),
		zap.Stringer("remote", c.RemoteAddr()),
		zap.NamedError("cause", cause),
	)
}
