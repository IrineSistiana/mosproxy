package router

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap"
)

const (
	defaultMaxConcurrentRequestPreTCPConn = 100
)

func (r *router) startTcpServer(cfg *ServerConfig, useTls bool) error {
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	maxConcurrent := cfg.Tcp.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequestPreTCPConn
	}

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

	s := &tcpServer{
		r:             r,
		l:             l,
		tlsConfig:     tlsConfig,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,
		ppv2:          cfg.ProtocolProxyV2,
		logger:        r.logger.Named("server_tcp").With(zap.Stringer("server_addr", l.Addr())),
	}
	s.logger.Info("tcp server started")
	go func() {
		defer l.Close()
		s.run()
	}()
	return nil
}

type tcpServer struct {
	r *router

	l             net.Listener
	tlsConfig     *tls.Config // maybe nil
	idleTimeout   time.Duration
	maxConcurrent int32
	ppv2          bool
	logger        *zap.Logger
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
	clientSrcAddr := netAddr2NetipAddr(c.RemoteAddr())
	clientDstAddr := netAddr2NetipAddr(c.LocalAddr())

	// Read pp2 header
	if s.ppv2 {
		c.SetReadDeadline(time.Now().Add(pp2HeaderReadTimeout))
		ppHdr, _, err := readIpFromPP2(c)
		c.SetReadDeadline(time.Time{})
		if err != nil {
			s.logger.Check(zap.ErrorLevel, "failed to read pp2 header").Write(
				zap.Stringer("so_remote", c.RemoteAddr()),
				zap.Error(err),
			)
			return
		}
		clientSrcAddr = ppHdr.SourceAddr
		clientDstAddr = ppHdr.DestinationAddr
	}

	// If server is tls enabled, do tls handshake here instead of
	// in the io calls. Because we can set deadline and handle error easily.
	if s.tlsConfig != nil {
		tlsConn := tls.Server(c, s.tlsConfig)
		defer tlsConn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			s.logger.Check(zap.WarnLevel, "failed to tls handshake").Write(
				zap.Stringer("local", clientDstAddr),
				zap.Stringer("remote", clientSrcAddr),
				zap.Error(err),
			)
			return
		}
		c = tlsConn
	}

	concurrent := new(atomic.Int32)
	emptyConn := true

	br := pool.BufReaderPool1K.Get()
	br.Reset(c)
	defer pool.BufReaderPool1K.Release(br)
	for {
		c.SetReadDeadline(time.Now().Add(s.idleTimeout))
		m, n, err := dnsutils.ReadMsgFromTCP(br)
		if err != nil {
			var errMsg string
			if n > 0 {
				errMsg = "invalid tcp msg"
			} else if emptyConn {
				errMsg = "empty tcp connection"
			}
			// Other cases: n == 0, has error, not empty conn.
			// Most likely are normal close or idle timeout.
			if len(errMsg) > 0 {
				s.logger.Check(zap.WarnLevel, errMsg).Write(
					zap.Stringer("local", clientDstAddr),
					zap.Stringer("remote", clientSrcAddr),
					zap.Error(err),
				)
			}
			return
		}
		emptyConn = false

		if concurrent.Add(1) > s.maxConcurrent {
			s.logger.Check(zap.WarnLevel, "too many concurrent requests").Write(
				zap.Stringer("local", clientDstAddr),
				zap.Stringer("remote", clientSrcAddr),
				zap.Error(err),
			)
			return
		}

		pool.Go(func() {
			s.handleReq(c, m, clientSrcAddr, clientDstAddr)
			dnsmsg.ReleaseMsg(m)
			concurrent.Add(-1)
		})
	}
}

func (s *tcpServer) handleReq(c net.Conn, m *dnsmsg.Msg, remoteAddr, localAddr netip.AddrPort) {
	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	defer releaseRequestContext(rc)

	s.r.handleServerReq(m, rc)

	buf, err := packRespTCP(rc.Response.Msg, true)
	if err != nil {
		s.logger.Error(logPackRespErr, zap.Error(err))
		return
	}

	_, err = c.Write(buf.B())
	pool.ReleaseBuf(buf)
	if err != nil {
		s.logger.Check(zap.WarnLevel, "write error").Write(
			zap.Stringer("local", localAddr),
			zap.Stringer("remote", remoteAddr),
			zap.Error(err),
		)
	}
}
