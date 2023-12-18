package router

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	defaultQuicIdleTimeout = time.Second * 30
	quicStreamReadTimeout  = time.Second
)

func (r *router) startQuicServer(cfg *ServerConfig) error {
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultQuicIdleTimeout
	}

	tlsConfig, err := makeTlsConfig(&cfg.Tls, true)
	if err != nil {
		return err
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
		return fmt.Errorf("failed to listen socket, %w", err)
	}

	srk, _, err := utils.InitQUICSrkFromIfaceMac()
	if err != nil {
		r.logger.Warn("failed to init quic stateless reset key, it will be disabled", zap.Error(err))
	}

	qt := &quic.Transport{
		Conn:              uc,
		StatelessResetKey: (*quic.StatelessResetKey)(srk),
	}
	l, err := qt.Listen(tlsConfig, quicConfig)
	if err != nil {
		qt.Close()
		return fmt.Errorf("failed to listen quic, %w", err)
	}

	s := &quicServer{
		r:           r,
		l:           l,
		idleTimeout: idleTimeout,
		logger:      r.logger.Named("server_quic").With(zap.Stringer("addr", l.Addr())),
	}
	s.logger.Info("quic server started")
	go func() {
		defer l.Close()
		s.run()
	}()
	return nil
}

type quicServer struct {
	r           *router
	l           *quic.Listener
	idleTimeout time.Duration
	logger      *zap.Logger
}

func (s *quicServer) run() {
	r := s.r
	for {
		c, err := s.l.Accept(context.Background())
		if err != nil {
			r.fatal("quic server exited", err)
			return
		}

		pool.Go(func() {
			defer c.CloseWithError(0, "")
			s.handleConn(c)
		})
	}
}

func (s *quicServer) handleConn(c quic.Connection) {
	localAddr := netAddr2NetipAddr(c.LocalAddr())
	remoteAddr := netAddr2NetipAddr(c.RemoteAddr())
	for {
		streamAcceptCtx, cancelAccept := context.WithTimeout(context.Background(), s.idleTimeout)
		stream, err := c.AcceptStream(streamAcceptCtx)
		cancelAccept()
		if err != nil {
			return
		}

		// Handle stream.
		// For doq, one stream, one query.
		pool.Go(func() {
			defer func() {
				stream.Close()
				stream.CancelRead(0) // TODO: Needs a proper error code.
			}()
			s.handleStream(stream, c, remoteAddr, localAddr)
		})
	}
}

func (s *quicServer) handleStream(stream quic.Stream, c quic.Connection, remoteAddr, localAddr netip.AddrPort) {
	r := s.r

	stream.SetReadDeadline(time.Now().Add(quicStreamReadTimeout))
	m, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil {
		s.logger.Check(zap.WarnLevel, "invalid quic msg").Write(
			zap.Stringer("local", c.LocalAddr()),
			zap.Stringer("remote", c.RemoteAddr()),
			zap.Error(err),
		)
	}
	defer dnsmsg.ReleaseMsg(m)

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	defer releaseRequestContext(rc)

	r.handleServerReq(m, rc)

	respBuf, err := packRespTCP(rc.Response.Msg, true)
	if err != nil {
		s.logger.Error(logPackRespErr, zap.Error(err))
		return
	}
	defer pool.ReleaseBuf(respBuf)
	if _, err := stream.Write(respBuf.B()); err != nil {
		s.logger.Check(zap.WarnLevel, "failed to write quic response").Write(
			zap.Stringer("local", c.LocalAddr()),
			zap.Stringer("remote", c.RemoteAddr()),
			zap.Error(err),
		)
	}
}
