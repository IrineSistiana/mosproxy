package router

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

const (
	defaultMaxConcurrentRequestPreTCPConn = 100
)

func (r *Router) startTcpServer(cfg *ServerConfig, useTls bool) (*tcpServer, error) {
	var tlsConfig *tls.Config
	if useTls {
		var err error
		tlsConfig, err = makeTlsConfig(&cfg.Tls, true)
		if err != nil {
			return nil, err
		}
	}

	l, err := r.listen(cfg)
	if err != nil {
		return nil, err
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
		logger:        r.subLoggerForServer("server_tcp", cfg.Tag),
		l:             l,
		tlsConfig:     tlsConfig,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,
		ct:            newConnTracker[net.Conn](func(c net.Conn) { c.Close() }, func() { l.Close() }),
	}
	s.logger.Info().
		Str("network", l.Addr().Network()).
		Stringer("addr", l.Addr()).
		Bool("tls", useTls).
		Msg("tcp server started")
	go func() {
		defer l.Close()
		err := s.run()
		if !errors.Is(err, errServerClosed) {
			s.r.fatal("tcp server exited", err)
		}
	}()
	return s, nil
}

type tcpServer struct {
	r      *Router
	logger *zerolog.Logger

	l             net.Listener
	tlsConfig     *tls.Config   // nil if tls is disabled
	idleTimeout   time.Duration // valid
	maxConcurrent int32         // valid

	ct *connTracker[net.Conn]
}

func (s *tcpServer) run() error {
	r := s.r
	for {
		c, err := s.l.Accept()
		if err != nil {
			if s.ct.Closed() {
				return errServerClosed
			}
			return err
		}

		debugLogServerConnAccepted(c, s.logger)

		var cost int
		if s.tlsConfig != nil {
			cost = costTLSConn
		} else {
			cost = costTCPConn
		}
		if err := r.limiterAllowN(netAddr2NetipAddr(c.RemoteAddr()).Addr(), cost); err != nil {
			// TODO: Log or create a metrics entry for refused queries.
			c.Close()
			debugLogServerConnClosed(c, s.logger, err)
		} else {
			if !s.ct.Add(c) {
				c.Close()
				continue
			}
			go func() {
				defer c.Close()
				defer s.ct.Del(c)
				s.handleConn(c)
			}()
		}
	}
}

func (s *tcpServer) handleConn(c net.Conn) {
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

	concurrent := new(atomic.Int32)
	respWriter := newTcpRespWriter(c, concurrent)
	br := pool.NewBR1K(c)
	defer pool.ReleaseBR1K(br)
	remoteAddr := netAddr2NetipAddr(c.RemoteAddr())
	localAddr := netAddr2NetipAddr(c.LocalAddr())
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

		cc := concurrent.Add(1)
		if cc > s.maxConcurrent ||
			s.r.limiterAllowN(netAddr2NetipAddr(c.RemoteAddr()).Addr(), costTCPQuery) != nil {
			resp := mustHaveEmptyRespForQueryB(m, dnsmsg.RCodeRefused, true, 0)
			c.Write(resp)
			pool.ReleaseBuf(resp)
			concurrent.Add(-1)
			//TODO: log or add an entry for refused queries.
		} else {
			s.r.handleQueryAsync(
				m,
				QueryMeta{RemoteAddr: remoteAddr, LocalAddr: localAddr},
				respWriter,
			)
		}
		dnsmsg.ReleaseMsg(m)
	}
}

type tcpRespWriter struct {
	c          net.Conn
	concurrent *atomic.Int32
}

func newTcpRespWriter(c net.Conn, concurrent *atomic.Int32) RespWriter {
	return &tcpRespWriter{
		c:          c,
		concurrent: concurrent,
	}
}

func (w *tcpRespWriter) WriteResp(m *dnsmsg.Msg) {
	// TODO: Impl write once
	b := mustHaveRespB(m, true, 0)
	w.c.Write(b)
	pool.ReleaseBuf(b)
	w.concurrent.Add(-1)
}

// Close the listener.
func (s *tcpServer) Close() error {
	s.ct.Close()
	return nil
}
