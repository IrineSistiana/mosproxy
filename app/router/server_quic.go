package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
)

const (
	defaultQuicIdleTimeout = time.Second * 30
	quicStreamReadTimeout  = time.Second
)

func (r *Router) startQuicServer(cfg *ServerConfig) (*quicServer, error) {
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultQuicIdleTimeout
	}

	tlsConfig, err := makeTlsConfig(&cfg.Tls, true)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{"doq"}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 idleTimeout,
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024,
		Allow0RTT:                      false,
		MaxIncomingStreams:             cfg.Quic.MaxStreams,
		// UniStream is not allowed.
		MaxIncomingUniStreams: -1,
	}

	uc, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to listen socket, %w", err)
	}

	qt := &quic.Transport{
		Conn: uc,
	}

	srk, _, err := utils.InitQUICSrkFromIfaceMac()
	if err == nil {
		qt.StatelessResetKey = (*quic.StatelessResetKey)(&srk)
	}

	l, err := qt.Listen(tlsConfig, quicConfig)
	if err != nil {
		qt.Close()
		return nil, fmt.Errorf("failed to listen quic, %w", err)
	}

	s := &quicServer{
		cfg:         cfg,
		r:           r,
		l:           l,
		idleTimeout: idleTimeout,
		logger:      r.subLoggerForServer("server_quic", cfg.Tag),
		ct:          newConnTracker(closeQuicConnServerClosing, func() { l.Close() }),
	}
	s.logger.Info().
		Stringer("addr", l.Addr()).
		Msg("quic server started")
	go func() {
		defer l.Close()
		err := s.run()
		if !errors.Is(err, errServerClosed) {
			r.Close(fmt.Errorf("quic server exited, %w", err))
		}
	}()
	return s, nil
}

func closeQuicConnServerClosing(c quic.Connection) {
	c.CloseWithError(0, "server is closing")
}

type quicServer struct {
	cfg         *ServerConfig
	r           *Router
	l           *quic.Listener
	idleTimeout time.Duration
	logger      *zerolog.Logger

	ct *connTracker[quic.Connection]
}

func (s *quicServer) run() error {
	for {
		c, err := s.l.Accept(context.Background())
		if err != nil {
			if s.ct.Closed() {
				return errServerClosed
			}
			return err
		}
		debugLogServerConnAccepted(c, s.logger)

		if !s.ct.Add(c) {
			closeQuicConnServerClosing(c)
			continue
		}
		go func() {
			defer s.ct.Del(c)
			defer c.CloseWithError(0, "")
			err := s.handleConn(c)
			debugLogServerConnClosed(c, s.logger, err)
		}()
	}
}

func (s *quicServer) handleConn(c quic.Connection) error {
	for {
		streamAcceptCtx, cancelAccept := context.WithTimeout(context.Background(), s.idleTimeout)
		stream, err := c.AcceptStream(streamAcceptCtx)
		cancelAccept()
		if err != nil {
			return err
		}

		// Handle stream.
		// For doq, one stream, one query.
		pool.Go(func() {
			defer func() {
				stream.Close()
				stream.CancelRead(0) // TODO: Needs a proper error code.
			}()
			s.handleStream(stream, c)
		})
	}
}

func (s *quicServer) handleStream(stream quic.Stream, c quic.Connection) {
	stream.SetReadDeadline(time.Now().Add(quicStreamReadTimeout))
	m, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil {
		s.logger.Warn().
			Stringer("remote", c.RemoteAddr()).
			Err(err).
			Msg("invalid query msg")
		return
	}
	defer dnsmsg.ReleaseMsg(m)

	q := NewQueryCtx()
	defer ReleaseQueryCtx(q)

	var respBuf pool.Buffer
	if ok := parseQuery(q, m); !ok {
		resp := makeEmptyRespM(m, dnsmsg.RCodeRefused)
		respBuf = serverFinalRespB(m, resp, true, 0)
		dnsmsg.ReleaseMsg(resp)
		goto sendResp
	}

	q.ServerTag = s.cfg.Tag
	q.Protocol = ProtoQUIC
	q.RemoteAddr = netAddr2NetipAddr(c.RemoteAddr())
	q.ServerName = append(q.ServerName, c.ConnectionState().TLS.ServerName...)

	s.r.serverEntryHandler(q)
	respBuf = serverFinalRespB(m, q.Resp, true, 0)

sendResp:
	if _, err = stream.Write(respBuf); err != nil {
		e := s.logger.Debug() // This err log might be annoying  Using debug log.
		if e != nil {
			e.Stringer("remote", c.RemoteAddr()).
				Err(err).
				Msg("failed to write to remote")
		}
	}
}

func (s *quicServer) Close() error {
	s.ct.Close()
	return nil
}
