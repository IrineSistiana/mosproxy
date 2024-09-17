package router

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
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

	ctx, cancel := context.WithCancelCause(context.Background())
	s := &tcpServer{
		cfg:           cfg,
		r:             r,
		logger:        r.subLoggerForServer("server_tcp", cfg.Tag),
		l:             l,
		tlsConfig:     tlsConfig,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,

		ctx:    ctx,
		cancel: cancel,
		ct:     newConnTracker[net.Conn](func(c net.Conn) { c.Close() }, func() { l.Close() }),
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
	cfg    *ServerConfig
	r      *Router
	logger *zerolog.Logger

	l             net.Listener
	tlsConfig     *tls.Config   // nil if tls is disabled
	idleTimeout   time.Duration // valid
	maxConcurrent int32         // valid

	ctx    context.Context
	cancel context.CancelCauseFunc
	ct     *connTracker[net.Conn]
}

func (s *tcpServer) run() error {
	for {
		c, err := s.l.Accept()
		if err != nil {
			if s.ct.Closed() {
				return errServerClosed
			}
			return err
		}
		debugLogServerConnAccepted(c, s.logger)

		if !s.ct.Add(c) {
			c.Close()
			debugLogServerConnClosed(c, s.logger, errServerClosed)
			continue
		}
		go func() {
			defer c.Close()
			defer s.ct.Del(c)
			err = s.handleConn(c)
			debugLogServerConnClosed(c, s.logger, err)
		}()
	}
}

func (s *tcpServer) handleConn(c net.Conn) error {
	// TLS handshake
	if s.tlsConfig != nil {
		tlsConn := tls.Server(c, s.tlsConfig)
		defer tlsConn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("failed to tls handshake, %w", err)
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
				return fmt.Errorf("invalid query msg, %w", err)
			}
			// eof, no err
			return nil
		}

		select {
		case concurrent <- struct{}{}:
			pool.Go(func() {
				defer dnsmsg.ReleaseMsg(m)
				defer func() {
					select {
					case <-concurrent:
					default:
						panic("negative concurrent counter")
					}
				}()
				s.handleMsg(c, m)
			})
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		}
	}
}

func (s *tcpServer) handleMsg(c net.Conn, m *dnsmsg.Msg) {
	q := NewQueryCtx()
	defer ReleaseQueryCtx(q)

	var respBuf pool.Buffer
	if ok := q.parseQuery(m); !ok {
		resp := makeEmptyRespM(m, dnsmsg.RCodeRefused)
		respBuf = serverFinalRespB(m, resp, true, 0)
		dnsmsg.ReleaseMsg(resp)
		goto sendResp
	}

	q.ServerTag = s.cfg.Tag
	q.RemoteAddr = netAddr2NetipAddr(c.RemoteAddr())
	if tc, ok := c.(*tls.Conn); ok {
		stat := tc.ConnectionState()
		q.Protocol = ProtoTLS
		q.ServerName = append(q.ServerName, stat.ServerName...)
	} else {
		q.Protocol = ProtoTCP
	}
	s.r.handleQuery(q)
	respBuf = serverFinalRespB(m, q.Resp, true, 0)

sendResp:
	_, err := c.Write(respBuf)
	pool.ReleaseBuf(respBuf)
	if err != nil {
		e := s.logger.Debug() // This err log might be annoying  Using debug log.
		if e != nil {
			e.Stringer("remote", c.RemoteAddr()).
				Err(err).
				Msg("failed to write to remote")
		}
	}
}

// Close the listener.
func (s *tcpServer) Close() error {
	s.ct.Close()
	return nil
}
