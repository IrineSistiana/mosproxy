package router

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

const (
	defaultMaxConcurrentRequestPreTCPConn = 100
)

func (r *router) startTcpServer(cfg *ServerConfig, useTls bool) error {
	var tlsConfig *tls.Config
	if useTls {
		var err error
		tlsConfig, err = makeTlsConfig(&cfg.Tls, true)
		if err != nil {
			return err
		}
	}

	l, err := r.listen(cfg)
	if err != nil {
		return err
	}

	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	maxConcurrent := cfg.Tcp.MaxConcurrentQueries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequestPreTCPConn
	}
	s := &tcpServer{
		r:             r,
		l:             l,
		tlsConfig:     tlsConfig,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,
		logger:        r.subLoggerForServer("server_tcp", cfg.Tag),
	}
	s.logger.Info().
		Str("network", l.Addr().Network()).
		Stringer("addr", l.Addr()).
		Msg("tcp server started")
	go func() {
		defer l.Close()
		s.run()
	}()
	return nil
}

type tcpServer struct {
	r *router

	l             net.Listener
	tlsConfig     *tls.Config   // nil if tls is disabled
	idleTimeout   time.Duration // valid
	maxConcurrent int32         // valid
	logger        *zerolog.Logger
}

func (s *tcpServer) run() {
	r := s.r
	for {
		c, err := s.l.Accept()
		if err != nil {
			r.fatal("tcp server exited", err)
			return
		}
		pool.Go(func() {
			defer c.Close()
			s.handleConn(c)
		})
	}
}

func (s *tcpServer) handleConn(c net.Conn) {
	debugLogServerConnAccepted(c, s.logger)

	// TLS handshake
	if s.tlsConfig != nil {
		tlsConn := tls.Server(c, s.tlsConfig)
		defer tlsConn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			s.logger.Warn().
				Stringer("local", c.LocalAddr()).
				Stringer("remote", c.RemoteAddr()).
				Err(err).
				Msg("failed to tls handshake")
			return
		}
		c = tlsConn
	}

	concurrent := make(chan struct{}, s.maxConcurrent)
	br := pool.NewBR1K(c)
	defer pool.ReleaseBR1K(br)
	for {
		c.SetReadDeadline(time.Now().Add(s.idleTimeout))
		m, n, err := dnsutils.ReadMsgFromTCP(br)
		if err != nil {
			if n > 0 { // invalid msg
				s.logger.Warn().
					Stringer("local", c.LocalAddr()).
					Stringer("remote", c.RemoteAddr()).
					Err(err).
					Msg("invalid query msg")
			}
			// eof
			debugLogServerConnClosed(c, s.logger, err)
			return
		}

		concurrent <- struct{}{}
		pool.Go(func() {
			defer func() { <-concurrent }()
			s.handleReq(c, m)
			dnsmsg.ReleaseMsg(m)
		})
	}
}

func (s *tcpServer) handleReq(c net.Conn, m *dnsmsg.Msg) {
	rc := getRequestContext()
	rc.RemoteAddr = netAddr2NetipAddr(c.RemoteAddr())
	rc.LocalAddr = netAddr2NetipAddr(c.LocalAddr())
	defer releaseRequestContext(rc)

	s.r.handleServerReq(m, rc)

	buf, err := packRespTCP(rc.Response.Msg, true)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg(logPackRespErr)
		return
	}

	_, err = c.Write(buf)
	pool.ReleaseBuf(buf)
	if err != nil {
		s.logger.Warn().
			Stringer("local", c.LocalAddr()).
			Stringer("remote", c.RemoteAddr()).
			Err(err).
			Msg("failed to write response")
		c.Close()
	}
}
