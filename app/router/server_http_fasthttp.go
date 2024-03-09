package router

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
)

func (r *router) startFastHttpServer(cfg *ServerConfig) error {
	const defaultIdleTimeout = time.Second * 30
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}

	l, err := r.listen(cfg)
	if err != nil {
		return err
	}

	h := &fasthttpHandler{
		r:                r,
		clientAddrHeader: cfg.Http.ClientAddrHeader,
		logger:           r.subLoggerForServer("server_fasthttp", cfg.Tag),
	}
	h.logger.Info().
		Str("network", l.Addr().Network()).
		Stringer("addr", l.Addr()).
		Msg("fasthttp server started")
	s := &fasthttp.Server{
		Handler:                      h.HandleFastHTTP,
		ReadTimeout:                  time.Second * 5,
		WriteTimeout:                 time.Second * 5,
		IdleTimeout:                  idleTimeout,
		MaxRequestBodySize:           65535,
		DisablePreParseMultipartForm: true,
		NoDefaultServerHeader:        true,
		NoDefaultDate:                true,
		StreamRequestBody:            true,
		Logger:                       log.New(mlog.WriteToLogger(*h.logger, "redirected fasthttp log", "msg"), "", 0),
	}

	go func() {
		defer l.Close()
		err := s.Serve(l)
		r.fatal("fasthttp server exited", err)
	}()
	return nil
}

type fasthttpHandler struct {
	r                *router
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

	// Maybe invalid. e.g. server is on unix socket.
	localAddr := netAddr2NetipAddr(ctx.LocalAddr())

	m := h.readReqMsg(ctx)
	if m == nil {
		return
	}
	defer dnsmsg.ReleaseMsg(m)

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	defer releaseRequestContext(rc)

	h.r.handleServerReq(m, rc)

	msgBody, err := packResp(rc.Response.Msg, true, 65535)
	if err != nil {
		h.logger.Error().
			Object("request", (*fasthttpReqLoggerObj)(ctx)).
			Err(err).
			Msg(logPackRespErr)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	defer pool.ReleaseBuf(msgBody)

	ctx.Response.Header.Add("Content-Type", "application/dns-message")
	ctx.SetBody(msgBody)
}

func readClientAddrFromXFFBytes(b []byte) (netip.Addr, error) {
	if i := bytes.IndexRune(b, ','); i > 0 {
		return netip.ParseAddr(bytes2StrUnsafe(b[:i]))
	}
	return netip.ParseAddr(bytes2StrUnsafe(b))
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
		if msgSize > 65535 {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Int("len", msgSize).
				Msg("query msg too long")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
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

		buf := bufPool.Get()
		defer bufPool.Release(buf)
		_, err := buf.ReadFrom(io.LimitReader(ctx.Request.BodyStream(), 65535))
		if err != nil {
			h.logger.Warn().
				Object("request", (*fasthttpReqLoggerObj)(ctx)).
				Err(err).
				Msg("failed to read request body")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.Bytes()

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
