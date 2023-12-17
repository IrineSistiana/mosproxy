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
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
		logger:           r.logger.Named("server_fasthttp").With(zap.Stringer("addr", l.Addr())),
	}
	h.logger.Info("fasthttp server started")
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
		Logger:                       log.New(mlog.WriteToLogger(h.logger, zap.WarnLevel, "", "msg"), "", 0),
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
	logger           *zap.Logger
}

type fasthttpReqLoggerObj fasthttp.RequestCtx

func (o *fasthttpReqLoggerObj) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	ctx := (*fasthttp.RequestCtx)(o)
	encoder.AddString("remote", ctx.Conn().RemoteAddr().String())
	encoder.AddString("local", ctx.Conn().LocalAddr().String())
	encoder.AddByteString("method", ctx.Method())
	encoder.AddByteString("url", ctx.URI().FullURI())
	encoder.AddByteString("proto", ctx.Request.Header.Protocol())
	encoder.AddByteString("ua", ctx.UserAgent())
	return nil
}

func fasthttpCtxField(ctx *fasthttp.RequestCtx) zap.Field {
	return zap.Object("req", (*fasthttpReqLoggerObj)(ctx))
}

func (h *fasthttpHandler) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	// check path
	if len(h.path) > 0 && h.path != string(ctx.Request.URI().Path()) {
		h.logger.Error("invalid path", fasthttpCtxField(ctx))
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}

	// Maybe invalid.
	var remoteAddr netip.AddrPort
	if header := h.clientAddrHeader; len(header) != 0 {
		if xff := ctx.Request.Header.Peek(header); len(xff) != 0 {
			addr, err := readClientAddrFromXFFBytes(xff)
			if err != nil {
				h.logger.Warn(
					"invalid client addr header",
					fasthttpCtxField(ctx),
					zap.ByteString("value", xff),
					zap.Error(err),
				)
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
		h.logger.Warn(logPackRespErr, fasthttpCtxField(ctx), zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	defer pool.ReleaseBuf(msgBody)

	ctx.Response.Header.Add("Content-Type", "application/dns-message")
	ctx.SetBody(msgBody.B())
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
			h.logger.Warn("invalid accept header", fasthttpCtxField(ctx), zap.ByteString("accept", acceptTyp))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}

		base64Dns := ctx.Request.URI().QueryArgs().Peek("dns")
		if len(base64Dns) == 0 {
			h.logger.Warn("missing dns parameter", fasthttpCtxField(ctx))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}

		msgSize := base64.RawURLEncoding.DecodedLen(len(base64Dns))
		if msgSize > 65535 {
			h.logger.Warn("query msg overflowed", fasthttpCtxField(ctx), zap.Int("len", msgSize))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		buf := pool.GetBuf(msgSize)
		defer pool.ReleaseBuf(buf)
		_, err := base64.RawURLEncoding.Decode(buf.B(), base64Dns)
		if err != nil {
			h.logger.Warn("invalid base64", fasthttpCtxField(ctx), zap.Error(err))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.B()

	case ctx.IsPost():
		// Check Content-Type header
		if ct := ctx.Request.Header.Peek("Content-Type"); string(ct) != "application/dns-message" {
			h.logger.Warn("invalid content-type header", fasthttpCtxField(ctx), zap.ByteString("content-type", ct))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}

		buf := bufPool.Get()
		defer bufPool.Release(buf)
		_, err := buf.ReadFrom(io.LimitReader(ctx.Request.BodyStream(), 65535))
		if err != nil {
			h.logger.Warn("failed to read request body", fasthttpCtxField(ctx), zap.Error(err))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.Bytes()

	default:
		h.logger.Warn("invalid method", fasthttpCtxField(ctx))
		ctx.SetStatusCode(fasthttp.StatusNotImplemented)
		return nil
	}

	m, err := dnsmsg.UnpackMsg(reqWireMsg)
	if err != nil {
		h.logger.Warn("invalid query msg", fasthttpCtxField(ctx), zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return nil
	}
	return m
}
