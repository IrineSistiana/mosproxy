package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/upstream/transport"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
)

const (
	tlsHandshakeTimeout = time.Second * 3

	// Maximum number of concurrent queries in one pipeline connection.
	// See RFC 7766 7. Response Reordering.
	// TODO: Make this configurable?
	pipelineConcurrentLimit = 64
)

type Upstream = transport.Transport

type Opt struct {
	// DialAddr specifies the address the upstream will
	// actually dial to in the network layer by overwriting
	// the address inferred from upstream url.
	// It won't affect high level layers. (e.g. SNI, HTTP HOST header won't be changed).
	// Can be an IP or a domain. Port is optional.
	// Tips: If the upstream url host is a domain, specific an IP address
	// here can skip resolving ip of this domain.
	//
	// Special usage:
	// If DialAddr has a "@" prefix, and the upstream protocol is stream/tcp based (tcp/tls/http/https),
	// then it will dial an abstract unix socket.
	DialAddr string

	// IdleTimeout specifies the timeout for dialing new connection.
	// Default value is about 3~5s (depending on upstream protocol and system settings).
	DialTimeout time.Duration

	// IdleTimeout specifies the idle timeout for long-connections.
	// Default: TCP, DoT: 10s , DoH, DoH3, DoQ: 30s.
	IdleTimeout time.Duration

	// EnablePipeline enables query pipelining support as RFC 7766 6.2.1.1 suggested.
	// Available for TCP, DoT upstream.
	// Note: There is no fallback. Make sure the server supports it.
	EnablePipeline bool

	// EnableHTTP3 will use HTTP/3 protocol to connect a DoH upstream. (aka DoH3).
	// Note: There is no fallback. Make sure the server supports it.
	EnableHTTP3 bool

	// TLSConfig specifies the tls.Config that the TLS client will use.
	// Available for DoT, DoH, DoQ upstream.
	TLSConfig *tls.Config

	// Logger specifies the logger that the upstream will use.
	Logger *zerolog.Logger

	// Set the Control field in net.ListenConfig / net.Dialer when creating
	// upstream connections.
	Control func(network, address string, c syscall.RawConn) error
}

// NewUpstream creates a upstream.
// addr has the format of: [protocol://]host[:port][/path].
// Supported protocol: udp/tcp/tls/https/quic. Default protocol is udp.
//
// Helper protocol:
//   - tcp+pipeline/tls+pipeline: Automatically set opt.EnablePipeline to true.
//   - h3: Automatically set opt.EnableHTTP3 to true.
func NewUpstream(addr string, opt Opt) (_ Upstream, err error) {
	logger := opt.Logger
	if logger == nil {
		logger = mlog.Nop()
	}

	// parse protocol and server addr
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address, %w", err)
	}

	// Apply helper protocol
	switch addrURL.Scheme {
	case "tcp+pipeline", "tls+pipeline":
		addrURL.Scheme = addrURL.Scheme[:3]
		opt.EnablePipeline = true
	case "h3":
		addrURL.Scheme = "https"
		opt.EnableHTTP3 = true
	}

	// If host is a ipv6 without port, it will be in []. This will cause err when
	// split and join address and port. Try to remove brackets now.
	urlAddrHost := tryTrimIpv6Brackets(addrURL.Host)

	dialer := &net.Dialer{
		Control: opt.Control,
	}

	closeIfFuncErr := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	switch addrURL.Scheme {
	case "", "udp":
		dialAddr := getDialAddr(urlAddrHost, opt.DialAddr, "53")
		dialUdp := func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", dialAddr)
		}
		ut := transport.NewPipelineTransport(transport.PipelineOpts{
			DialContext:        dialUdp,
			DialTimeout:        opt.DialTimeout,
			IdleTimeout:        time.Minute,
			IsTCP:              false,
			MaxConcurrentQuery: 4096,
			Logger:             logger,
		})

		dialTcp := func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddr)
		}
		return &udpWithFallback{
			u: ut,
			t: transport.NewReuseConnTransport(transport.ReuseConnOpts{
				DialContext: dialTcp,
				DialTimeout: opt.DialTimeout,
				Logger:      logger,
			}),
		}, nil
	case "tcp":
		idleTimeout := opt.IdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = time.Second * 10
		}
		dialAddr := getDialAddr(urlAddrHost, opt.DialAddr, "53")
		dialTCP := func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, dialNetworkTcpOrUnix(dialAddr), dialAddr)
		}
		if opt.EnablePipeline {
			return transport.NewPipelineTransport(transport.PipelineOpts{
				DialContext:        dialTCP,
				DialTimeout:        opt.DialTimeout,
				IsTCP:              true,
				MaxConcurrentQuery: pipelineConcurrentLimit,
				IdleTimeout:        idleTimeout,
				Logger:             logger,
			}), nil
		}
		return transport.NewReuseConnTransport(transport.ReuseConnOpts{
			DialContext: dialTCP,
			IdleTimeout: idleTimeout,
			Logger:      logger,
		}), nil
	case "tls":
		idleTimeout := opt.IdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = time.Second * 10
		}

		tlsConfig := opt.TLSConfig.Clone()
		if tlsConfig == nil {
			tlsConfig = new(tls.Config)
		}
		if len(tlsConfig.ServerName) == 0 {
			tlsConfig.ServerName = tryRemovePort(urlAddrHost)
		}

		dialAddr := getDialAddr(urlAddrHost, opt.DialAddr, "853")
		dialTLS := func(ctx context.Context) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, dialNetworkTcpOrUnix(dialAddr), dialAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tlsConn.Close()
				return nil, err
			}
			return tlsConn, nil
		}

		if opt.EnablePipeline {
			return transport.NewPipelineTransport(transport.PipelineOpts{
				DialContext:        dialTLS,
				DialTimeout:        opt.DialTimeout,
				IsTCP:              true,
				MaxConcurrentQuery: pipelineConcurrentLimit,
				IdleTimeout:        idleTimeout,
				Logger:             logger,
			}), nil
		}
		return transport.NewReuseConnTransport(transport.ReuseConnOpts{
			DialContext: dialTLS,
			DialTimeout: opt.DialTimeout,
			IdleTimeout: idleTimeout,
			Logger:      logger,
		}), nil
	case "https", "http":
		var defaultPort string
		if addrURL.Scheme == "http" {
			defaultPort = "80"
		} else {
			defaultPort = "443"
		}
		dialAddr := getDialAddr(urlAddrHost, opt.DialAddr, defaultPort)
		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}

		var t http.RoundTripper
		var addonCloser io.Closer
		if opt.EnableHTTP3 {
			if addrURL.Scheme == "http" {
				return nil, errors.New("invalid scheme http in h3 upstream")
			}
			lc := net.ListenConfig{Control: opt.Control}
			conn, err := lc.ListenPacket(context.Background(), "udp", "")
			if err != nil {
				return nil, fmt.Errorf("failed to init udp socket for quic, %w", err)
			}
			quicTransport := &quic.Transport{
				Conn: conn,
			}
			defer closeIfFuncErr(quicTransport)

			quicConfig := newDefaultClientQuicConfig()
			quicConfig.MaxIdleTimeout = idleConnTimeout

			addonCloser = quicTransport
			t = &http3.RoundTripper{
				TLSClientConfig: opt.TLSConfig,
				QuicConfig:      quicConfig,
				Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					ua, err := net.ResolveUDPAddr("udp", dialAddr)
					if err != nil {
						return nil, err
					}
					return quicTransport.DialEarly(ctx, ua, tlsCfg, cfg)
				},
				MaxResponseHeaderBytes: 4 * 1024,
			}
		} else {
			t1 := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, dialNetworkTcpOrUnix(dialAddr), dialAddr)
				},
				TLSClientConfig:     opt.TLSConfig,
				TLSHandshakeTimeout: tlsHandshakeTimeout,
				IdleConnTimeout:     idleConnTimeout,

				// Following opts are for http/1 only.
				MaxConnsPerHost:     0,
				MaxIdleConnsPerHost: 1024, // default 2
			}

			t2, err := http2.ConfigureTransports(t1)
			if err != nil {
				return nil, fmt.Errorf("failed to upgrade http2 support, %w", err)
			}
			t2.MaxHeaderListSize = 4 * 1024
			t2.MaxReadFrameSize = 16 * 1024
			t2.ReadIdleTimeout = time.Second * 30
			t2.PingTimeout = time.Second * 5
			t = t1
		}
		opt := transport.DoHTransportOpts{
			EndPointUrl:  addrURL.String(),
			RoundTripper: t,
			Closer:       addonCloser,
			Logger:       logger,
		}
		u, err := transport.NewDoHTransport(opt)
		if err != nil {
			return nil, fmt.Errorf("failed to create doh upstream, %w", err)
		}
		return u, nil
	case "quic", "doq":
		dialAddr := getDialAddr(urlAddrHost, opt.DialAddr, "853")
		tlsConfig := opt.TLSConfig.Clone()
		if tlsConfig == nil {
			tlsConfig = new(tls.Config)
		}
		if len(tlsConfig.ServerName) == 0 {
			tlsConfig.ServerName = tryRemovePort(urlAddrHost)
		}
		tlsConfig.NextProtos = []string{"doq"}

		quicConfig := newDefaultClientQuicConfig()
		if opt.IdleTimeout > 0 {
			quicConfig.MaxIdleTimeout = opt.IdleTimeout
		}
		// Don't accept stream.
		quicConfig.MaxIncomingStreams = -1
		quicConfig.MaxIncomingUniStreams = -1

		lc := net.ListenConfig{Control: opt.Control}
		uc, err := lc.ListenPacket(context.Background(), "udp", "")
		if err != nil {
			return nil, fmt.Errorf("failed to init udp socket for quic, %w", err)
		}

		t := &quic.Transport{
			Conn: uc,
		}
		srk, _, err := utils.InitQUICSrkFromIfaceMac()
		if err != nil {
			t.StatelessResetKey = (*quic.StatelessResetKey)(&srk)
		}
		closeIfFuncErr(t)

		dialQuicConn := func(ctx context.Context) (quic.Connection, error) {
			ua, err := net.ResolveUDPAddr("udp", dialAddr)
			if err != nil {
				return nil, err
			}
			// This is a workaround to
			// 1. recover from strange 0rtt rejected err.
			// 2. avoid NextConnection might block forever.
			// TODO: Remove this workaround.
			var c quic.Connection
			ec, err := t.DialEarly(ctx, ua, tlsConfig, quicConfig)
			if err != nil {
				return nil, err
			}
			select {
			case <-ctx.Done():
				err := context.Cause(ctx)
				ec.CloseWithError(0, "")
				return nil, err
			case <-ec.HandshakeComplete():
				c = ec.NextConnection()
			}
			return c, nil
		}
		return transport.NewQuicTransport(transport.QuicTransportOpts{
			DialContext: dialQuicConn,
			Logger:      logger,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported protocol [%s]", addrURL.Scheme)
	}
}

type udpWithFallback struct {
	u *transport.PipelineTransport
	t *transport.ReuseConnTransport
}

func (u *udpWithFallback) ExchangeContext(ctx context.Context, q []byte) (*dnsmsg.Msg, error) {
	r, err := u.u.ExchangeContext(ctx, q)
	if err != nil {
		return nil, err
	}
	if r.Header.Truncated {
		dnsmsg.ReleaseMsg(r)
		return u.t.ExchangeContext(ctx, q)
	}
	return r, nil
}

func (u *udpWithFallback) Close() error {
	u.u.Close()
	u.t.Close()
	return nil
}

func newDefaultClientQuicConfig() *quic.Config {
	return &quic.Config{
		TokenStore: quic.NewLRUTokenStore(4, 8),

		// Dns does not need large amount of io, so the rx/tx windows are small.
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024,

		MaxIdleTimeout:       time.Second * 30,
		KeepAlivePeriod:      time.Second * 25,
		HandshakeIdleTimeout: tlsHandshakeTimeout,
	}
}
