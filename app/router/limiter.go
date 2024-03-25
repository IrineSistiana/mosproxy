package router

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/limiter"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

const (
	// server side
	costUDPQuery  = 1
	costTCPQuery  = 2
	costHTTPQuery = 2
	costQUICQuery = 2
	costTCPConn   = 3
	costTLSConn   = 15
	costQuicConn  = 15

	// client side
	costFromCache    = 1
	costFromUpstream = 3
)

var (
	errGlobalResLimit = errors.New("reached global resource limit")
	errClientResLimit = errors.New("reached client resource limit")
)

type resourceLimiter struct {
	global *rate.Limiter          // nil if no limit
	cl     *limiter.ClientLimiter // nil if no limit
}

// Return errGlobalRateLimit, errClientRateLimit, or nil.
func (l *resourceLimiter) AllowN(addr netip.Addr, n int) error {
	now := time.Now()
	if l.global != nil {
		if !l.global.AllowN(now, n) {
			return errGlobalResLimit
		}
	}
	if l.cl != nil {
		if !l.cl.AllowN(addr, now, n) {
			return errClientResLimit
		}
	}
	return nil
}

func (l *resourceLimiter) Close() error {
	if l.cl != nil {
		l.cl.Close()
	}
	return nil
}

func initResourceLimiter(cfg LimiterConfig) *resourceLimiter {
	l := new(resourceLimiter)
	if cfg.GlobalLimit > 0 {
		l.global = rate.NewLimiter(rate.Limit(cfg.GlobalLimit), cfg.GlobalLimit)
	}
	if cfg.Client.Limit > 0 {
		l.cl = limiter.NewClientLimiter(limiter.ClientLimiterOpts{
			Limit:  float64(cfg.Client.Limit),
			Burst:  cfg.Client.Burst,
			V4Mask: cfg.Client.V4Mask,
			V6Mask: cfg.Client.V6Mask,
		})
	}
	return l
}

type listener struct {
	net.Listener                  // not nil
	logger       *zerolog.Logger  // not nil
	limiter      *resourceLimiter // not nil
	connCost     int
}

func newListener(l net.Listener, logger *zerolog.Logger, limiter *resourceLimiter, connCost int) *listener {
	return &listener{
		Listener: l,
		logger:   logger,
		limiter:  limiter,
		connCost: connCost,
	}
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		debugLogServerConnAccepted(c, l.logger)
		remoteAddr := netAddr2NetipAddr(c.RemoteAddr()).Addr()
		if remoteAddr.IsValid() {
			err = l.limiter.AllowN(remoteAddr, l.connCost)
			if err != nil {
				c.Close()
				debugLogServerConnClosed(c, l.logger, err)
				continue
			}
		}
		return c, nil
	}
}
