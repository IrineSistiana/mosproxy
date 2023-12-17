//go:build linux

package router

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/panjf2000/gnet/v2"
	"go.uber.org/zap"
)

func (r *router) startGnetServer(cfg *ServerConfig) error {
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	maxConcurrent := cfg.Tcp.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequestPreTCPConn
	}
	engineNum := cfg.Tcp.EngineNum
	if engineNum <= 1 {
		engineNum = 1
	}

	var proto string
	if strings.HasPrefix(cfg.Listen, "@") {
		proto = "unix"
	} else {
		proto = "tcp"
	}
	addr := proto + "://" + cfg.Listen
	logger := r.logger.Named("server_gnet").With(zap.String("engine_addr", addr))
	e := &engine{
		logger:        logger,
		r:             r,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,
	}

	e.logger.Info("engine is starting")
	socketOpts := cfg.Socket // TODO: Impl all options.
	go func() {
		err := gnet.Run(e, addr,
			gnet.WithNumEventLoop(engineNum),
			gnet.WithSocketRecvBuffer(socketOpts.SO_RCVBUF),
			gnet.WithSocketSendBuffer(socketOpts.SO_SNDBUF),
			gnet.WithReusePort(socketOpts.SO_REUSEPORT),
			gnet.WithLogger(logger.Sugar()),
			gnet.WithReadBufferCap(2+65535), // This is the maximum tcp payload.
		)
		r.fatal("gnet engine exited", err)
	}()

	return nil
}

type engine struct {
	logger *zap.Logger
	r      *router

	idleTimeout   time.Duration
	maxConcurrent int
}

type connCtx struct {
	// ctx
	ctx    context.Context
	cancel context.CancelCauseFunc // will be called when conn was closed.

	// info, static, may be invalid, e.g. unix socket
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort

	// counter
	concurrentRequests atomic.Int32
}

// OnBoot fires when the engine is ready for accepting connections.
// The parameter engine has information and various utilities.
func (e *engine) OnBoot(eng gnet.Engine) (action gnet.Action) {
	e.logger.Info("engine started")
	return gnet.None
}

// OnShutdown fires when the engine is being shut down, it is called right after
// all event-loops and connections are closed.
func (e *engine) OnShutdown(eng gnet.Engine) {
	e.logger.Info("engine stopped")
}

// OnOpen fires when a new connection has been opened.
//
// The Conn c has information about the connection such as its local and remote addresses.
// The parameter out is the return value which is going to be sent back to the peer.
// Sending large amounts of data back to the peer in OnOpen is usually not recommended.
func (e *engine) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	ctx, cancel := context.WithCancelCause(context.Background())
	// TODO: Reuse cc?
	cc := &connCtx{
		ctx:        ctx,
		cancel:     cancel,
		remoteAddr: netAddr2NetipAddr(c.RemoteAddr()),
		localAddr:  netAddr2NetipAddr(c.LocalAddr()),
	}
	c.SetContext(cc)
	c.SetReadDeadline(time.Now().Add(e.idleTimeout))
	return nil, gnet.None
}

// OnClose fires when a connection has been closed.
// The parameter err is the last known connection error.
func (e *engine) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	cc := c.Context().(*connCtx)
	cc.cancel(err)
	if e.r.opt.logInvalid && err != nil && !errors.Is(err, io.EOF) {
		// TODO: This log will be annoying. So the lvl is debug. Filter out the common errors?
		e.logger.Check(zap.DebugLevel, "conn closed").Write(
			zap.Stringer("remote", cc.remoteAddr),
			zap.Stringer("local", cc.localAddr),
			zap.Error(err),
		)
	}
	return gnet.None
}

// OnTraffic fires when a socket receives data from the peer.
//
// Note that the []byte returned from Conn.Peek(int)/Conn.Next(int) is not allowed to be passed to a new goroutine,
// as this []byte will be reused within event-loop after OnTraffic() returns.
// If you have to use this []byte in a new goroutine, you should either make a copy of it or call Conn.Read([]byte)
// to read data into your own []byte, then pass the new []byte to the new goroutine.
func (e *engine) OnTraffic(c gnet.Conn) (action gnet.Action) {
	cc := c.Context().(*connCtx)

	// Read all msgs in the buffer.
	for {
		// Check read buffer, is there a fully msg?
		hdr, err := c.Peek(2)
		if err != nil {
			if err == bufio.ErrBufferFull {
				panic("gnet recv buffer is too small")
			}
			break // partial hdr
		}

		l := binary.BigEndian.Uint16(hdr)
		hdrBody, err := c.Peek(2 + int(l))
		if err != nil {
			if err == bufio.ErrBufferFull {
				panic("gnet recv buffer is too small")
			}
			break // partial body
		}

		// full body

		if int(cc.concurrentRequests.Load()) > e.maxConcurrent {
			// Too many concurrent requests.
			// TODO: Return a REFUSE instead of closing the connection?
			e.logger.Check(zap.WarnLevel, "too many concurrent requests").Write(
				zap.Stringer("remote", cc.remoteAddr),
				zap.Stringer("local", cc.localAddr),
				zap.Error(err),
			)
			return gnet.Close
		}

		m, err := dnsmsg.UnpackMsg(hdrBody[2:])
		c.Discard(2 + int(l))
		c.SetReadDeadline(time.Now().Add(e.idleTimeout))
		if err != nil {
			if e.r.opt.logInvalid {
				e.logger.Check(zap.WarnLevel, "invalid msg").Write(
					zap.Stringer("remote", cc.remoteAddr),
					zap.Stringer("local", cc.localAddr),
					zap.Error(err),
				)
			}
			return gnet.Close
		}

		pool.Go(func() {
			rc := getRequestContext()
			rc.RemoteAddr = cc.remoteAddr
			rc.LocalAddr = cc.localAddr
			defer releaseRequestContext(rc)

			e.r.handleServerReq(m, rc)
			dnsmsg.ReleaseMsg(m)

			buf, err := packRespTCP(rc.Response.Msg, true)
			if err != nil {
				e.logger.Error(logPackRespErr, zap.Error(err))
				return
			}

			err = c.AsyncWrite(buf.B(), func(c gnet.Conn, err error) error {
				pool.ReleaseBuf(buf)
				if err == nil {
					err = c.Flush()
				}
				cc.concurrentRequests.Add(-1)
				if err != nil && e.r.opt.logInvalid {
					e.logger.Check(zap.WarnLevel, "failed to write").Write(
						zap.Stringer("remote", cc.remoteAddr),
						zap.Stringer("local", cc.localAddr),
						zap.Error(err),
					)
				}
				return nil
			})
			if err != nil && e.r.opt.logInvalid {
				e.logger.Check(zap.WarnLevel, "failed to async write").Write(
					zap.Stringer("remote", cc.remoteAddr),
					zap.Stringer("local", cc.localAddr),
					zap.Error(err),
				)
			}
		})
	}
	return gnet.None
}

// OnTick fires immediately after the engine starts and will fire again
// following the duration specified by the delay return value.
func (e *engine) OnTick() (delay time.Duration, action gnet.Action) {
	return
}
