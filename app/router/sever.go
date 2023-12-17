package router

import (
	"errors"
	"fmt"
)

var (
	errListenerClosed   = errors.New("listener closed")
	errClientConnClosed = errors.New("client connection closed")
)

func (r *router) startServer(cfg *ServerConfig) error {
	switch cfg.Protocol {
	case "", "udp":
		return r.startUdpServer(cfg)
	case "tcp":
		return r.startTcpServer(cfg, false)
	case "gnet":
		return r.startGnetServer(cfg)
	case "tls":
		return r.startTcpServer(cfg, true)
	case "http":
		return r.startHttpServer(cfg, false)
	case "fasthttp":
		return r.startFastHttpServer(cfg)
	case "https":
		return r.startHttpServer(cfg, true)
	case "quic":
		return r.startQuicServer(cfg)
	default:
		return fmt.Errorf("invalid server protocol [%s]", cfg.Protocol)
	}
}
