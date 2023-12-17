package router

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/pp"
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
		logger:        r.logger.Named("server_tcp").With(zap.Stringer("addr", l.Addr())),
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
	maxConcurrent int
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
	r := s.r
	// Read pp2 header
	var ppHdr pp.HeaderV2 // maybe zero
	if s.ppv2 {
		c.SetReadDeadline(time.Now().Add(pp2HeaderReadTimeout))
		var err error
		ppHdr, _, err = pp.ReadV2(c)
		c.SetReadDeadline(time.Time{})
		if err != nil {
			s.logger.Error(
				"failed to read pp2 header",
				zap.Stringer("local", c.LocalAddr()),
				zap.Stringer("remote", c.RemoteAddr()),
				zap.Error(err),
			)
			return
		}
	}

	// tls conn or a bufio reader.
	// Note: tls conn is already a, some kind of, buffered reader.
	var connReader io.Reader

	// If server is tls enabled, do tls handshake here instead of
	// in the io calls. Because we can set deadline and handle error easily.
	if s.tlsConfig != nil {
		tlsConn := tls.Server(c, s.tlsConfig)
		defer tlsConn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			if r.opt.logInvalid {
				s.logger.Check(zap.WarnLevel, "failed to tls handshake").Write(
					zap.Stringer("local", c.LocalAddr()),
					zap.Stringer("remote", c.RemoteAddr()),
					zap.Error(err),
				)
			}
			return
		}
		c = tlsConn
		connReader = c
	} else {
		br := pool.BufReaderPool1K.Get()
		br.Reset(c)
		defer pool.BufReaderPool1K.Release(br)
		connReader = br
	}

	// Maybe invalid. e.g. No pp2 header and c is unix socket.
	localAddr := firstValidAddr(ppHdr.DestinationAddr, c.LocalAddr())
	remoteAddr := firstValidAddr(ppHdr.SourceAddr, c.RemoteAddr())

	connCtx, cancelConn := context.WithCancelCause(context.Background())
	defer cancelConn(errClientConnClosed)

	// Start conn write loop.
	writeChan := make(chan *pool.Buffer, 8)
	pool.Go(func() {
		err := tcpWriteLoop(connCtx, c, writeChan)
		if err != nil {
			if s.r.opt.logInvalid {
				s.logger.Check(zap.WarnLevel, "failed to write tcp response").Write(
					zap.Stringer("local", c.LocalAddr()),
					zap.Stringer("remote", c.RemoteAddr()),
					zap.Error(err),
				)
			}
		}
	})

	concurrentLimiter := make(chan struct{}, s.maxConcurrent)
	emptyConn := true
	for {
		c.SetReadDeadline(time.Now().Add(s.idleTimeout))
		m, n, err := dnsutils.ReadMsgFromTCP(connReader)
		if err != nil {
			if r.opt.logInvalid {
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
						zap.Stringer("local", firstValidAddrStringer(ppHdr.DestinationAddr, c.LocalAddr())),
						zap.Stringer("remote", firstValidAddrStringer(ppHdr.SourceAddr, c.RemoteAddr())),
						zap.Error(err),
					)
				}
			}
			return
		}
		emptyConn = false

		concurrentLimiter <- struct{}{}
		pool.Go(func() {
			s.handleReq(connCtx, c, writeChan, m, remoteAddr, localAddr)
			dnsmsg.ReleaseMsg(m)
			<-concurrentLimiter
		})
	}
}

// Note: asyncWriteMsg takes the ownership of the payload.
func asyncWriteMsg(ctx context.Context, ch chan *pool.Buffer, payload *pool.Buffer) error {
	select {
	case <-ctx.Done():
		defer pool.ReleaseBuf(payload)
		return fmt.Errorf("failed to send payload to write queue, %w", context.Cause(ctx))
	case ch <- payload:
		return nil
	}
}

func tcpWriteLoop(ctx context.Context, c net.Conn, ch chan *pool.Buffer) error {
	bw := pool.BufWriterPool1K.Get()
	bw.Reset(c)
	defer pool.BufWriterPool1K.Release(bw)

	for {
		select {
		case <-ctx.Done():
			return nil
		case b := <-ch:
			_, err := bw.Write(b.B())
			pool.ReleaseBuf(b)
			if err != nil {
				return err
			}
		readMore:
			for {
				select {
				case b := <-ch:
					_, err := bw.Write(b.B())
					pool.ReleaseBuf(b)
					if err != nil {
						return err
					}
				default:
					break readMore
				}
			}
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
	}
}

func (s *tcpServer) handleReq(connCtx context.Context, c net.Conn, wc chan *pool.Buffer, m *dnsmsg.Msg, remoteAddr, localAddr netip.AddrPort) {
	r := s.r

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	defer releaseRequestContext(rc)

	r.handleServerReq(m, rc)

	buf, err := packRespTCP(rc.Response.Msg, true)
	if err != nil {
		s.logger.Error(logPackRespErr, zap.Error(err))
		return
	}

	err = asyncWriteMsg(connCtx, wc, buf)
	if err != nil && s.r.opt.logInvalid {
		s.logger.Check(zap.WarnLevel, "failed to write tcp response").Write(
			zap.Stringer("local", c.LocalAddr()),
			zap.Stringer("remote", c.RemoteAddr()),
			zap.Error(err),
		)
	}
}
