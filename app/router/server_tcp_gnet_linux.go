//go:build linux

package router

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog"
)

func (r *router) startGnetServer(cfg *ServerConfig) error {
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	maxConcurrent := cfg.Tcp.MaxConcurrentQueries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequestPreTCPConn
	}

	var proto string
	if strings.HasPrefix(cfg.Listen, "@") {
		proto = "unix"
	} else {
		proto = "tcp"
	}
	addr := proto + "://" + cfg.Listen
	e := &gnetEngine{
		logger:        r.subLoggerForServer("server_gnet", cfg.Tag),
		r:             r,
		idleTimeout:   idleTimeout,
		maxConcurrent: maxConcurrent,
	}

	socketOpts := cfg.Socket // TODO: Impl all options.
	go func() {
		cpuNum := runtime.NumCPU()
		if cpuNum > 4 {
			cpuNum = 4
		}
		e.logger.Info().
			Str("addr", addr).
			Int("threads", cpuNum).
			Msg("gnet engine is starting")

		err := gnet.Run(e, addr,
			gnet.WithNumEventLoop(cpuNum),
			gnet.WithSocketRecvBuffer(socketOpts.SO_RCVBUF),
			gnet.WithSocketSendBuffer(socketOpts.SO_SNDBUF),
			gnet.WithReusePort(socketOpts.SO_REUSEPORT),
			gnet.WithLogger(&gnetLogger{l: *e.logger}),
			gnet.WithReadBufferCap(128*1024), // Note: minimum is 65535+2 (maximum tcp payload).
		)
		r.fatal("gnet engine exited", err)
	}()

	return nil
}

type gnetEngine struct {
	r      *router
	logger *zerolog.Logger

	idleTimeout   time.Duration
	maxConcurrent int32
}

type connCtx struct {
	// info, static, may be invalid, e.g. unix socket
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort

	// counter
	concurrentRequests atomic.Int32
}

// OnBoot fires when the engine is ready for accepting connections.
// The parameter engine has information and various utilities.
func (e *gnetEngine) OnBoot(eng gnet.Engine) (action gnet.Action) {
	e.logger.Info().Msg("engine started")
	return gnet.None
}

// OnShutdown fires when the engine is being shut down, it is called right after
// all event-loops and connections are closed.
func (e *gnetEngine) OnShutdown(eng gnet.Engine) {
	e.logger.Info().Msg("engine stopped")
}

// OnOpen fires when a new connection has been opened.
//
// The Conn c has information about the connection such as its local and remote addresses.
// The parameter out is the return value which is going to be sent back to the peer.
// Sending large amounts of data back to the peer in OnOpen is usually not recommended.
func (e *gnetEngine) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	debugLogServerConnAccepted(c, e.logger)

	// TODO: Reuse cc?
	cc := &connCtx{
		remoteAddr: netAddr2NetipAddr(c.RemoteAddr()),
		localAddr:  netAddr2NetipAddr(c.LocalAddr()),
	}
	c.SetContext(cc)
	c.SetReadDeadline(time.Now().Add(e.idleTimeout))
	return nil, gnet.None
}

// OnClose fires when a connection has been closed.
// The parameter err is the last known connection error.
func (e *gnetEngine) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	debugLogServerConnClosed(c, e.logger, err)
	cc := c.Context().(*connCtx)

	e.logger.Debug(). // TODO: Remove this.
				Stringer("remote", cc.remoteAddr).
				Stringer("local", cc.localAddr).
				Err(err).
				Msg("conn closed")
	return gnet.None
}

// OnTraffic fires when a socket receives data from the peer.
//
// Note that the []byte returned from Conn.Peek(int)/Conn.Next(int) is not allowed to be passed to a new goroutine,
// as this []byte will be reused within event-loop after OnTraffic() returns.
// If you have to use this []byte in a new goroutine, you should either make a copy of it or call Conn.Read([]byte)
// to read data into your own []byte, then pass the new []byte to the new goroutine.
func (e *gnetEngine) OnTraffic(c gnet.Conn) (action gnet.Action) {
	cc := c.Context().(*connCtx)

	// Read all msgs in the buffer.
	for {
		// Check read buffer, is there a fully msg?
		hdr, err := c.Peek(2)
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				panic("gnet recv buffer is too small")
			}
			break // partial hdr
		}

		l := binary.BigEndian.Uint16(hdr)
		hdrBody, err := c.Peek(2 + int(l))
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				panic("gnet recv buffer is too small")
			}
			break // partial body
		}

		// full body

		if cc.concurrentRequests.Load() > e.maxConcurrent {
			// Too many concurrent requests.
			// TODO: Return a REFUSE instead of closing the connection?
			e.logger.Warn().
				Stringer("remote", cc.remoteAddr).
				Stringer("local", cc.localAddr).
				Msg("too many concurrent requests")
			return gnet.Close
		}

		m, err := dnsmsg.UnpackMsg(hdrBody[2:])
		c.Discard(2 + int(l))
		c.SetReadDeadline(time.Now().Add(e.idleTimeout))
		if err != nil {
			e.logger.Warn().
				Stringer("remote", cc.remoteAddr).
				Stringer("local", cc.localAddr).
				Err(err).
				Msg("invalid msg")
			return gnet.Close
		}

		pool.Go(func() {
			rc := getRequestContext()
			defer releaseRequestContext(rc)
			rc.RemoteAddr = cc.remoteAddr
			rc.LocalAddr = cc.localAddr

			e.r.handleServerReq(m, rc)
			dnsmsg.ReleaseMsg(m)

			buf, err := packRespTCP(rc.Response.Msg, true)
			if err != nil {
				e.logger.Error().
					Err(err).
					Msg(logPackRespErr)
				return
			}

			err = c.AsyncWrite(buf, func(c gnet.Conn, err error) error {
				pool.ReleaseBuf(buf)
				if err == nil {
					err = c.Flush()
				}
				cc.concurrentRequests.Add(-1)
				if err != nil {
					e.logger.Warn().
						Stringer("remote", cc.remoteAddr).
						Stringer("local", cc.localAddr).
						Err(err).
						Msg("failed to write resp")
				}
				return nil
			})
			if err != nil {
				e.logger.Warn().
					Stringer("remote", cc.remoteAddr).
					Stringer("local", cc.localAddr).
					Err(err).
					Msg("failed to async write resp")
			}
		})
	}
	return gnet.None
}

// OnTick fires immediately after the engine starts and will fire again
// following the duration specified by the delay return value.
func (e *gnetEngine) OnTick() (delay time.Duration, action gnet.Action) {
	return
}

type gnetLogger struct {
	l zerolog.Logger
}

func (l *gnetLogger) Debugf(format string, args ...interface{}) {
	l.l.Debug().Msgf(format, args...)
}

func (l *gnetLogger) Infof(format string, args ...interface{}) {
	l.l.Info().Msgf(format, args...)
}

func (l *gnetLogger) Warnf(format string, args ...interface{}) {
	l.l.Warn().Msgf(format, args...)
}

func (l *gnetLogger) Errorf(format string, args ...interface{}) {
	l.l.Error().Msgf(format, args...)
}

func (l *gnetLogger) Fatalf(format string, args ...interface{}) {
	l.l.Fatal().Msgf(format, args...)
}
