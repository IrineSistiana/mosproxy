package router

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
)

func (r *router) startHttpServer(cfg *ServerConfig, useTls bool) error {
	const defaultIdleTimeout = time.Second * 30
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}

	h := &httpHandler{
		r:                r,
		clientAddrHeader: cfg.Http.ClientAddrHeader,
	}

	hs := &http.Server{
		Handler:        h,
		ReadTimeout:    time.Second * 5,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 4096,
	}

	if err := http2.ConfigureServer(hs, &http2.Server{
		MaxReadFrameSize:             16 * 1024, // http2 minimum
		MaxConcurrentStreams:         cfg.Http.TestMaxStreams,
		IdleTimeout:                  idleTimeout,
		MaxUploadBufferPerConnection: 65535, // http2 minimum
		MaxUploadBufferPerStream:     65535, // http2 minimum
	}); err != nil {
		return fmt.Errorf("failed to setup http2 server, %w", err)
	}

	if useTls {
		tlsConfig, err := makeTlsConfig(&cfg.Tls, true)
		if err != nil {
			return err
		}
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		hs.TLSConfig = tlsConfig
	}

	l, err := r.listen(cfg)
	if err != nil {
		return err
	}
	h.localAddr = netAddr2NetipAddr(l.Addr()) // maybe nil
	h.logger = r.logger.Named("server_http").With(zap.Stringer("addr", l.Addr()))
	hs.ErrorLog = log.New(mlog.WriteToLogger(h.logger, zap.WarnLevel, "", "msg"), "", 0)

	h.logger.Info("http server started")
	go func() {
		defer l.Close()
		var err error
		if useTls {
			err = hs.ServeTLS(l, "", "")
		} else {
			err = hs.Serve(l)
		}
		r.fatal("http server exited", err)
	}()
	return nil
}

type httpHandler struct {
	r                *router
	localAddr        netip.AddrPort // maybe invalid, e.g. server is on unix socket
	path             string
	clientAddrHeader string

	logger *zap.Logger
}

type httpReqLoggerObj http.Request

func (req *httpReqLoggerObj) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("client", req.RemoteAddr)
	encoder.AddString("method", req.Method)
	encoder.AddString("url", req.RequestURI)
	encoder.AddString("proto", req.Proto)
	return nil
}

func reqField(req *http.Request) zap.Field {
	return zap.Object("req", (*httpReqLoggerObj)(req))
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// check path
	if len(h.path) > 0 && h.path != req.URL.Path {
		h.logger.Error("invalid path", reqField(req))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// get client addr
	var remoteAddr netip.AddrPort
	if header := h.clientAddrHeader; len(header) != 0 {
		if xff := req.Header.Get(header); len(xff) != 0 {
			addr, err := readClientAddrFromXFF(xff)
			if err != nil {
				h.logger.Warn("invalid client addr header", reqField(req), zap.String("value", xff), zap.Error(err))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			remoteAddr = netip.AddrPortFrom(addr, 0)
		}
	} else {
		// get remote addr from http. Maybe invalid. e.g. server is on unix socket.
		remoteAddr, _ = netip.ParseAddrPort(req.RemoteAddr)
	}

	m := h.readReqMsg(w, req)
	if m == nil {
		return
	}
	defer dnsmsg.ReleaseMsg(m)

	resp := h.r.handleServerReq(req.Context(), m, remoteAddr, h.localAddr)
	defer dnsmsg.ReleaseMsg(resp)

	buf, err := packResp(resp, true, 65535)
	if err != nil {
		h.logger.Error(logPackRespErr, reqField(req), zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer pool.ReleaseBuf(buf)

	w.Header().Set("Content-Type", "application/dns-message")
	if _, err := w.Write(buf.B()); err != nil {
		h.logger.Check(zap.DebugLevel, "failed to write http response").Write(
			reqField(req),
			zap.Error(err),
		)
		return
	}
}

func readClientAddrFromXFF(s string) (netip.Addr, error) {
	if i := strings.IndexRune(s, ','); i > 0 {
		return netip.ParseAddr(s[:i])
	}
	return netip.ParseAddr(s)
}

var bufPool = pool.NewBytesBufPool(4096)

func getDnsKey(query string) string {
	for len(query) > 0 {
		var key string
		key, query, _ = strings.Cut(query, "&")
		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		if key == "dns" {
			return value
		}
	}
	return ""
}

func (h *httpHandler) readReqMsg(w http.ResponseWriter, req *http.Request) *dnsmsg.Msg {
	var reqWireMsg []byte
	switch req.Method {
	case http.MethodGet:
		// Check accept header
		if acceptTyp := req.Header.Get("Accept"); acceptTyp != "application/dns-message" {
			h.logger.Warn("invalid accept header", reqField(req), zap.String("accept", acceptTyp))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		s := getDnsKey(req.URL.RawQuery)
		if len(s) == 0 {
			h.logger.Warn("missing dns parameter", reqField(req))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		msgSize := base64.RawURLEncoding.DecodedLen(len(s))
		if msgSize > 65535 {
			h.logger.Warn("query msg overflowed", reqField(req), zap.Int("len", msgSize))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		buf := pool.GetBuf(msgSize)
		defer pool.ReleaseBuf(buf)
		_, err := base64.RawURLEncoding.Decode(buf.B(), str2BytesUnsafe(s))
		if err != nil {
			h.logger.Warn("invalid base64", reqField(req), zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.B()

	case http.MethodPost:
		// Check Content-Type header
		if ct := req.Header.Get("Content-Type"); ct != "application/dns-message" {
			h.logger.Warn("invalid content-type header", reqField(req), zap.String("content-type", ct))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		buf := bufPool.Get()
		defer bufPool.Release(buf)
		_, err := buf.ReadFrom(io.LimitReader(req.Body, 65535))
		if err != nil {
			h.logger.Warn("failed to read request body", reqField(req), zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.Bytes()

	default:
		h.logger.Warn("invalid method", reqField(req))
		w.WriteHeader(http.StatusNotImplemented)
		return nil
	}

	m, err := dnsmsg.UnpackMsg(reqWireMsg)
	if err != nil {
		h.logger.Warn("invalid query msg", reqField(req), zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	return m
}
