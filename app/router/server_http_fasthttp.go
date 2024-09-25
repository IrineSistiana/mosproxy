package router

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
)

func (r *Router) startFastHttpServer(cfg *ServerConfig) (*fastHttpServer, error) {
	const defaultIdleTimeout = time.Second * 30
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}

	l, err := r.listen(cfg)
	if err != nil {
		return nil, err
	}

	logger := r.subLoggerForServer("server_fasthttp", cfg.Tag)
	h := &fasthttpHandler{
		cfg:              cfg,
		r:                r,
		clientAddrHeader: cfg.Http.ClientAddrHeader,
		logger:           logger,
	}
	h.logger.Info().
		Str("network", l.Addr().Network()).
		Stringer("addr", l.Addr()).
		Msg("fasthttp server started")

	fs := &fasthttp.Server{
		Handler:      h.HandleFastHTTP,
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
		IdleTimeout:  idleTimeout,

		// TODO: Configurable buffer size?
		ReadBufferSize:     512,
		WriteBufferSize:    512,
		MaxRequestBodySize: 512,

		DisablePreParseMultipartForm: true,
		NoDefaultServerHeader:        true,
		NoDefaultDate:                true,
		StreamRequestBody:            false,
		Logger:                       log.New(mlog.WriteToLogger(logger, "redirected fasthttp log", "msg"), "", 0),
	}

	s := newFastHttpServer(fs, l, logger)
	go func() {
		defer l.Close()
		err := s.serve()
		if err != nil {
			if !errors.Is(err, errServerClosed) {
				r.Close(fmt.Errorf("fasthttp server exited, %w", err))
			}
		}
	}()
	return s, nil
}

type fastHttpServer struct {
	s      *fasthttp.Server
	l      net.Listener
	logger *zerolog.Logger

	ct *connTracker[net.Conn]
}

func newFastHttpServer(s *fasthttp.Server, l net.Listener, logger *zerolog.Logger) *fastHttpServer {
	return &fastHttpServer{
		s:      s,
		l:      l,
		logger: logger,
		ct:     newConnTracker(func(c net.Conn) { c.Close() }, func() { l.Close() }),
	}
}

func (s *fastHttpServer) serve() error {
	for {
		c, err := s.l.Accept()
		if err != nil {
			if s.ct.Closed() {
				return errServerClosed
			}
			return err
		}

		if !s.ct.Add(c) {
			c.Close()
			continue
		}
		pool.Go(func() {
			defer s.ct.Del(c)
			err := s.s.ServeConn(c)
			if err != nil {
				s.logger.Warn().Err(err).
					Stringer("local", c.LocalAddr()).
					Stringer("remote", c.RemoteAddr()).
					Msg("failed to serve conn")
			}
		})
	}
}

func (s *fastHttpServer) Close() error {
	s.ct.Close()
	return nil
}

type fasthttpHandler struct {
	cfg              *ServerConfig
	r                *Router
	path             string
	clientAddrHeader string
	logger           *zerolog.Logger
}

type fasthttpReqLoggerObj fasthttp.RequestCtx

func (o *fasthttpReqLoggerObj) MarshalZerologObject(e *zerolog.Event) {
	ctx := (*fasthttp.RequestCtx)(o)
	e.Bytes("proto", ctx.Request.Header.Protocol())
	e.Bytes("method", ctx.Method())
	e.Bytes("url", ctx.URI().FullURI())
	e.Bytes("ua", ctx.UserAgent())
	e.Str("remote", ctx.Conn().RemoteAddr().String())
	e.Str("local", ctx.Conn().LocalAddr().String())
}

func (h *fasthttpHandler) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	// check path
	if len(h.path) > 0 && h.path != string(ctx.Request.URI().Path()) {
		h.logger.Warn().
			Object("request", (*fasthttpReqLoggerObj)(ctx)).
			Msg("invalid path")
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}

	// Maybe invalid.
	var remoteAddr netip.AddrPort
	if header := h.clientAddrHeader; len(header) != 0 {
		if xff := ctx.Request.Header.Peek(header); len(xff) != 0 {
			addr, err := readClientAddrFromXFFBytes(xff)
			if err != nil {
				h.logger.Warn().
					Object("request", (*fasthttpReqLoggerObj)(ctx)).
					Bytes("value", xff).
					Err(err).
					Msg("invalid client addr header value")
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				return
			}
			remoteAddr = netip.AddrPortFrom(addr, 0)
		}
	} else {
		addr := ctx.RemoteAddr()
		remoteAddr = netAddr2NetipAddr(addr) // Maybe invalid. e.g. server is on unix socket.
	}

	m := h.readReqMsg(ctx)
	if m == nil {
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
	} else {
		q.ServerTag = h.cfg.Tag
		q.RemoteAddr = remoteAddr
		if stat := ctx.TLSConnectionState(); stat != nil {
			q.Protocol = ProtoHTTPS
			q.ServerName = append(q.ServerName, stat.ServerName...)
		} else {
			q.Protocol = ProtoHTTP
		}
		q.Host = append(q.Host, ctx.Host()...)
		q.Path = append(q.Path, ctx.Path()...)

		h.r.serverEntryHandler(q)
		respBuf = serverFinalRespB(m, q.Resp, false, udpSize)
	}

	ctx.Response.Header.Add("Content-Type", "application/dns-message")
	ctx.SetBody(respBuf)
	pool.ReleaseBuf(respBuf)
}

func readClientAddrFromXFFBytes(b []byte) (netip.Addr, error) {
	if i := bytes.IndexRune(b, ','); i > 0 {
		return netip.ParseAddr(utils.Bytes2StrUnsafe(b[:i]))
	}
	return netip.ParseAddr(utils.Bytes2StrUnsafe(b))
}

func (h *fasthttpHandler) readReqMsg(ctx *fasthttp.RequestCtx) *dnsmsg.Msg {
	var reqWireMsg []byte
	switch {
	case ctx.IsGet():
		// Check accept header
		if acceptTyp := ctx.Request.Header.Peek("Accept"); string(acceptTyp) != "application/dns-message" {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Bytes("value", acceptTyp).
				Msg("invalid accept header")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}

		base64Dns := ctx.Request.URI().QueryArgs().Peek("dns")
		if len(base64Dns) == 0 {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Msg("missing dns parameter")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}

		msgSize := base64.RawURLEncoding.DecodedLen(len(base64Dns))
		if msgSize > maxHttpGetPayload {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Int("len", msgSize).
				Msg("query msg too long")
			ctx.SetStatusCode(fasthttp.StatusRequestURITooLong)
			return nil
		}
		buf := pool.GetBuf(msgSize)
		defer pool.ReleaseBuf(buf)
		_, err := base64.RawURLEncoding.Decode(buf, base64Dns)
		if err != nil {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Err(err).
				Msg("invalid base64 data")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf

	case ctx.IsPost():
		// Check Content-Type header
		if ct := ctx.Request.Header.Peek("Content-Type"); string(ct) != "application/dns-message" {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Bytes("value", ct).
				Msg("invalid content-type header")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		reqWireMsg = ctx.Request.Body()

	default:
		h.logger.Warn().
			Object("request", (*fasthttpReqLoggerObj)(ctx)).
			Msg("invalid method")
		ctx.SetStatusCode(fasthttp.StatusNotImplemented)
		return nil
	}

	m, err := dnsmsg.UnpackMsg(reqWireMsg)
	if err != nil {
		h.logger.Warn().
			Object("request", (*fasthttpReqLoggerObj)(ctx)).
			Err(err).
			Msg("invalid query msg")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return nil
	}
	return m
}
