//go:build linux

package router

import (
	"encoding/binary"
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
		)
		r.fatal("gnet engine exited", err)
	}()

	return nil
}

type gnetEngine struct {
	r      *router
	logger *zerolog.Logger // not nil

	idleTimeout   time.Duration // valid
	maxConcurrent int32         // valid
}

type connCtx struct {
	// info, static, may be invalid, e.g. unix socket
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort

	// counter
	concurrentRequests atomic.Int32

	idleTimer *time.Timer // from time.After

	readN      int
	buffer     pool.Buffer // buffer for partial read msg, maybe nil
	readingHdr bool        // length of the msg waiting to read

	err error // first error that occur
}

func (cc *connCtx) saveFirstErr(err error) {
	if cc.err == nil {
		cc.err = err
	}
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
		idleTimer:  time.AfterFunc(e.idleTimeout, func() { c.Close() }),
	}
	c.SetContext(cc)

	if err := e.r.limiterAllowN(cc.remoteAddr.Addr(), costTCPConn); err != nil {
		// TODO: Log or create a metrics entry for refused queries.
		cc.saveFirstErr(err)
		return nil, gnet.Close
	}
	return nil, gnet.None
}

// OnClose fires when a connection has been closed.
// The parameter err is the last known connection error.
func (e *gnetEngine) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	cc := c.Context().(*connCtx)
	cc.idleTimer.Stop()

	closeErr := err
	if cc.err != nil { // log cc.err which is more useful (e.g. invalid msg...)
		closeErr = cc.err
	}
	debugLogServerConnClosed(c, e.logger, closeErr)
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
	cc.idleTimer.Reset(e.idleTimeout)

read:
	var (
		m   *dnsmsg.Msg
		err error
	)
	if cc.buffer != nil { // TODO: Add test for partial read.
		if cc.readingHdr {
			hdrRemains := len(cc.buffer) - cc.readN
			b, _ := c.Next(hdrRemains)
			cc.readN += copy(cc.buffer[cc.readN:], b)
			if cc.readN < 2 {
				return gnet.None
			}
			msgLen := binary.BigEndian.Uint16(cc.buffer)
			pool.ReleaseBuf(cc.buffer)
			cc.buffer = pool.GetBuf(int(msgLen))
			cc.readN = 0
			cc.readingHdr = false
		}

		bodyRemains := len(cc.buffer) - cc.readN
		b, _ := c.Next(bodyRemains)
		cc.readN += copy(cc.buffer[cc.readN:], b)
		if cc.readN < len(cc.buffer) {
			return gnet.None
		}
		m, err = dnsmsg.UnpackMsg(cc.buffer)
		pool.ReleaseBuf(cc.buffer)
		cc.buffer = nil
	} else {
		// read hdr
		hdr, _ := c.Next(2)
		if len(hdr) < 2 {
			cc.buffer = pool.GetBuf(2)
			cc.readN = copy(cc.buffer, hdr)
			cc.readingHdr = true
			return gnet.None // partial hdr
		}
		l := int(binary.BigEndian.Uint16(hdr))

		// read body
		body, _ := c.Next(l)
		if len(body) < l {
			cc.buffer = pool.GetBuf(l)
			cc.readN = copy(cc.buffer, body)
			cc.readingHdr = false
			return gnet.None // partial body
		}
		m, err = dnsmsg.UnpackMsg(body)
	}

	if err != nil { // invalid msg
		e.logger.Warn().
			Stringer("remote", cc.remoteAddr).
			Stringer("local", cc.localAddr).
			Err(err).
			Msg("invalid msg")
		cc.saveFirstErr(err)
		return gnet.Close
	}

	ccr := cc.concurrentRequests.Add(1)
	if ccr > e.maxConcurrent { // Too many concurrent requests.
		resp := mustHaveRespB(m, nil, dnsmsg.RCodeRefused, true, 0)
		c.Write(resp)
		cc.concurrentRequests.Add(-1)
		dnsmsg.ReleaseMsg(m)
		pool.ReleaseBuf(resp)
		// TODO: Log or create a metrics entry for refused queries.
	} else {
		go func() {
			rc := getRequestContext()
			defer releaseRequestContext(rc)
			rc.RemoteAddr = cc.remoteAddr
			rc.LocalAddr = cc.localAddr

			e.r.handleServerReq(m, rc)
			dnsmsg.ReleaseMsg(m)

			buf := mustHaveRespB(m, rc.Response.Msg, dnsmsg.RCodeRefused, true, 0)
			err := c.AsyncWrite(buf, func(c gnet.Conn, err error) error {
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
		}()
	}

	if c.InboundBuffered() > 0 {
		goto read
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
