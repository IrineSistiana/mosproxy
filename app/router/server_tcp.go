package router

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
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

func (r *router) startTcpServer(cfg *ServerConfig, useTls bool) (*tcpServer, error) {
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
	r      *router
	logger *zerolog.Logger

	l             net.Listener
	tlsConfig     *tls.Config   // nil if tls is disabled
	idleTimeout   time.Duration // valid
	maxConcurrent int32         // valid

	closeOnce sync.Once
	closed    atomic.Bool
}

func (s *tcpServer) run() error {
	r := s.r
	for {
		c, err := s.l.Accept()
		if err != nil {
			if s.closed.Load() {
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
			go func() {
				s.handleConn(c)
				c.Close()
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

	var concurrent atomic.Int32
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
			resp := mustHaveRespB(m, nil, dnsmsg.RCodeRefused, true, 0)
			c.Write(resp)
			pool.ReleaseBuf(resp)
			concurrent.Add(-1)
			//TODO: log or add an entry for refused queries.
		} else {
			rc := getRequestContext()
			rc.RemoteAddr = remoteAddr
			rc.LocalAddr = localAddr
			go func() {
				s.handleReq(c, m, rc)
				dnsmsg.ReleaseMsg(m)
				releaseRequestContext(rc)
				concurrent.Add(-1)
			}()
		}
	}
}

func (s *tcpServer) handleReq(c net.Conn, m *dnsmsg.Msg, rc *RequestContext) {
	s.r.handleServerReq(m, rc)
	buf := mustHaveRespB(m, rc.Response.Msg, dnsmsg.RCodeRefused, true, 0)
	_, err := c.Write(buf)
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

// Close the listener.
func (s *tcpServer) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.l.Close()
	})
	return nil
}
