package router

import (
	"errors"
	"fmt"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

var (
	errServerClosed = errors.New("server closed")
)

func (r *Router) startServer(cfg *ServerConfig) (closeFn func(), err error) {
	switch cfg.Protocol {
	case "", "udp":
		s, err := r.startUdpServer(cfg)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "tcp":
		s, err := r.startTcpServer(cfg, false)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "tls":
		s, err := r.startTcpServer(cfg, true)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "http":
		s, err := r.startHttpServer(cfg, false)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "fasthttp":
		s, err := r.startFastHttpServer(cfg)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "https":
		s, err := r.startHttpServer(cfg, true)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "http3":
		s, err := r.startHttp3Server(cfg)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	case "quic":
		s, err := r.startQuicServer(cfg)
		if err != nil {
			return nil, err
		}
		return func() { s.Close() }, nil
	default:
		return nil, fmt.Errorf("invalid server protocol [%s]", cfg.Protocol)
	}
}

type RespWriter interface {
	// Must be called once.
	WriteResp(m *dnsmsg.Msg)
}
