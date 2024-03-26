package router

import (
	"errors"
	"fmt"
)

var (
	errServerClosed = errors.New("server closed")
)

func (r *router) startServer(cfg *ServerConfig) (func(), error) {
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
	case "gnet":
		s, err := r.startGnetServer(cfg)
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
		return func() { s.Shutdown() }, nil
	case "https":
		s, err := r.startHttpServer(cfg, true)
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
