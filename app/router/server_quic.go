package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
)

const (
	defaultQuicIdleTimeout = time.Second * 30
	quicStreamReadTimeout  = time.Second
)

func (r *router) startQuicServer(cfg *ServerConfig) (*quicServer, error) {
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
		r:           r,
		l:           l,
		idleTimeout: idleTimeout,
		logger:      r.subLoggerForServer("server_quic", cfg.Tag),
	}
	s.logger.Info().
		Stringer("addr", l.Addr()).
		Msg("quic server started")
	go func() {
		defer l.Close()
		err := s.run()
		if !errors.Is(err, errServerClosed) {
			r.fatal("quic server exited", err)
		}
	}()
	return s, nil
}

type quicServer struct {
	r           *router
	l           *quic.Listener
	idleTimeout time.Duration
	logger      *zerolog.Logger

	closeOnce sync.Once
	closed    atomic.Bool
}

func (s *quicServer) run() error {
	r := s.r
	for {
		c, err := s.l.Accept(context.Background())
		if err != nil {
			if s.closed.Load() {
				return errServerClosed
			}
			return err
		}
		debugLogServerConnAccepted(c, s.logger)

		if err := r.limiterAllowN(netAddr2NetipAddr(c.LocalAddr()).Addr(), costQuicConn); err != nil {
			debugLogServerConnClosed(c, s.logger, err)
			c.CloseWithError(0, "service unavailable, overloaded")
		} else {
			go func() {
				err := s.handleConn(c)
				debugLogServerConnClosed(c, s.logger, err)
				c.CloseWithError(0, "")
			}()
		}
	}
}

func (s *quicServer) handleConn(c quic.Connection) error {
	localAddr := netAddr2NetipAddr(c.LocalAddr())
	remoteAddr := netAddr2NetipAddr(c.RemoteAddr())
	for {
		streamAcceptCtx, cancelAccept := context.WithTimeout(context.Background(), s.idleTimeout)
		stream, err := c.AcceptStream(streamAcceptCtx)
		cancelAccept()
		if err != nil {
			return err
		}

		if err := s.r.limiterAllowN(remoteAddr.Addr(), costQUICQuery); err != nil {
			// TODO: Send dns REFUSE instead of close the quic stream
			// without any info?
			// TODO: Log or create a metrics entry for refused queries.
			stream.Close()
			stream.CancelRead(0)
			continue
		}

		// Handle stream.
		// For doq, one stream, one query.
		go func() {
			defer func() {
				stream.Close()
				stream.CancelRead(0) // TODO: Needs a proper error code.
			}()
			s.handleStream(stream, c, remoteAddr, localAddr)
		}()
	}
}

func (s *quicServer) handleStream(stream quic.Stream, c quic.Connection, remoteAddr, localAddr netip.AddrPort) {
	r := s.r

	stream.SetReadDeadline(time.Now().Add(quicStreamReadTimeout))
	m, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil {
		s.logger.Warn().
			Stringer("local", c.LocalAddr()).
			Stringer("remote", c.RemoteAddr()).
			Err(err).
			Msg("invalid query msg")
		return
	}
	defer dnsmsg.ReleaseMsg(m)

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	defer releaseRequestContext(rc)

	r.handleServerReq(m, rc)

	respBuf := mustHaveRespB(m, rc.Response.Msg, dnsmsg.RCodeRefused, true, 0)
	defer pool.ReleaseBuf(respBuf)
	if _, err := stream.Write(respBuf); err != nil {
		s.logger.Warn().
			Stringer("local", c.LocalAddr()).
			Stringer("remote", c.RemoteAddr()).
			Err(err).
			Msg("failed to write response")
	}
}

func (s *quicServer) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.l.Close()
	})
	return nil
}
