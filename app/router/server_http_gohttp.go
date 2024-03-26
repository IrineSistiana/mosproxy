package router

import (
	"encoding/base64"
	"errors"
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
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
)

func (r *router) startHttpServer(cfg *ServerConfig, useTls bool) (*http.Server, error) {
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
		MaxConcurrentStreams:         cfg.Http.DebugMaxStreams,
		IdleTimeout:                  idleTimeout,
		MaxUploadBufferPerConnection: 65535, // http2 minimum
		MaxUploadBufferPerStream:     65535, // http2 minimum
	}); err != nil {
		return nil, fmt.Errorf("failed to setup http2 server, %w", err)
	}

	if useTls {
		tlsConfig, err := makeTlsConfig(&cfg.Tls, true)
		if err != nil {
			return nil, err
		}
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		hs.TLSConfig = tlsConfig
	}

	l, err := r.listen(cfg)
	if err != nil {
		return nil, err
	}
	h.localAddr = netAddr2NetipAddr(l.Addr()) // maybe nil
	h.logger = r.subLoggerForServer("server_http", cfg.Tag)
	hs.ErrorLog = log.New(mlog.WriteToLogger(*h.logger, "redirected http log", "msg"), "", 0)

	var cost int
	if useTls {
		cost = costTLSConn
	} else {
		cost = costTCPConn
	}
	l = newListener(l, h.logger, r.limiter, cost)

	h.logger.Info().
		Str("network", l.Addr().Network()).
		Stringer("addr", l.Addr()).
		Msg("http server started")
	go func() {
		defer l.Close()
		var err error
		if useTls {
			err = hs.ServeTLS(l, "", "")
		} else {
			err = hs.Serve(l)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			r.fatal("http server exited", err)
		}
	}()
	return hs, nil
}

type httpHandler struct {
	r                *router
	localAddr        netip.AddrPort // maybe invalid, e.g. server is on unix socket
	path             string
	clientAddrHeader string

	logger *zerolog.Logger
}

type httpReqLoggerObj http.Request

// Note: keep key names same as [fasthttpReqLoggerObj]
func (req *httpReqLoggerObj) MarshalZerologObject(e *zerolog.Event) {
	e.Str("proto", req.Proto)
	e.Str("method", req.Method)
	e.Str("url", req.RequestURI)
	e.Str("ua", req.Header.Get("User-Agent"))
	e.Str("remote", req.RemoteAddr)
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// check path
	if len(h.path) > 0 && h.path != req.URL.Path {
		h.logger.Warn().
			Object("request", (*httpReqLoggerObj)(req)).
			Msg("invalid path")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// get client addr
	var remoteAddr netip.AddrPort
	if header := h.clientAddrHeader; len(header) != 0 {
		if xff := req.Header.Get(header); len(xff) != 0 {
			addr, err := readClientAddrFromXFF(xff)
			if err != nil {
				h.logger.Warn().
					Object("request", (*httpReqLoggerObj)(req)).
					Str("value", xff).
					Err(err).
					Msg("invalid client addr header value")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			remoteAddr = netip.AddrPortFrom(addr, 0)
		}
	} else {
		// get remote addr from http. Maybe invalid. e.g. server is on unix socket.
		remoteAddr, _ = netip.ParseAddrPort(req.RemoteAddr)
	}

	if err := h.r.limiterAllowN(remoteAddr.Addr(), costHTTPQuery); err != nil {
		// TODO: Log or create a metrics entry for refused queries.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	m := h.readReqMsg(w, req)
	if m == nil {
		return
	}
	defer dnsmsg.ReleaseMsg(m)

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = h.localAddr
	defer releaseRequestContext(rc)

	h.r.handleServerReq(m, rc)

	msgBody := mustHaveRespB(m, rc.Response.Msg, dnsmsg.RCodeRefused, false, 65535)
	defer pool.ReleaseBuf(msgBody)

	w.Header().Set("Content-Type", "application/dns-message")
	if _, err := w.Write(msgBody); err != nil {
		h.logger.Error().
			Object("request", (*httpReqLoggerObj)(req)).
			Err(err).
			Msg("failed to write http response")
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
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Str("value", acceptTyp).
				Msg("invalid accept header")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		s := getDnsKey(req.URL.RawQuery)
		if len(s) == 0 {
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Msg("missing dns parameter")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		msgSize := base64.RawURLEncoding.DecodedLen(len(s))
		if msgSize > 65535 {
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Int("len", msgSize).
				Msg("query msg too long")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		buf := pool.GetBuf(msgSize)
		defer pool.ReleaseBuf(buf)
		_, err := base64.RawURLEncoding.Decode(buf, utils.Str2BytesUnsafe(s))
		if err != nil {
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Err(err).
				Msg("invalid base64 data")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf

	case http.MethodPost:
		// Check Content-Type header
		if ct := req.Header.Get("Content-Type"); ct != "application/dns-message" {
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Str("value", ct).
				Msg("invalid content-type header")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}

		buf := bufPool.Get()
		defer bufPool.Release(buf)
		_, err := buf.ReadFrom(io.LimitReader(req.Body, 65535))
		if err != nil {
			h.logger.Warn().
				Object("request", (*httpReqLoggerObj)(req)).
				Err(err).
				Msg("failed to read request body")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		reqWireMsg = buf.Bytes()

	default:
		h.logger.Warn().
			Object("request", (*httpReqLoggerObj)(req)).
			Msg("invalid method")
		w.WriteHeader(http.StatusNotImplemented)
		return nil
	}

	m, err := dnsmsg.UnpackMsg(reqWireMsg)
	if err != nil {
		h.logger.Warn().
			Object("request", (*httpReqLoggerObj)(req)).
			Err(err).
			Msg("invalid query msg")
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	return m
}
