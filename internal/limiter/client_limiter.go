package limiter

import (
	"net/netip"
	"sync"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"golang.org/x/time/rate"
)

const (
	gcInterval = time.Second * 30
	entryTtl   = time.Minute
)

type ClientLimiterOpts struct {
	Limit  float64 // default 20
	Burst  int     // default is Qps
	V4Mask int     // default 24
	V6Mask int     // default 48
}

func (opts *ClientLimiterOpts) setDefault() {
	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	if opts.Burst <= 0 {
		opts.Burst = int(opts.Limit)
	}
	if m := opts.V4Mask; m <= 0 || m > 32 {
		opts.V4Mask = 24
	}
	if m := opts.V6Mask; m <= 0 || m > 128 {
		opts.V4Mask = 48
	}
}

type ClientLimiter struct {
	opts ClientLimiterOpts
	m    *xsync.MapOf[netip.Addr, *e]

	closeOnce   sync.Once
	closeNotify chan struct{}
}

type e struct {
	m        sync.Mutex
	l        *rate.Limiter
	lastSeen time.Time
}

// Creates a ClientLimiter.
// Note: Call ClientLimiter.Close() to stop its gc goroutine.
func NewClientLimiter(opts ClientLimiterOpts) *ClientLimiter {
	opts.setDefault()
	l := &ClientLimiter{
		opts:        opts,
		m:           xsync.NewMapOf[netip.Addr, *e](),
		closeNotify: make(chan struct{}),
	}
	go l.gcLoop()
	return l
}

func (cl *ClientLimiter) AllowN(addr netip.Addr, now time.Time, n int) bool {
	e, _ := cl.m.LoadOrCompute(cl.mask(addr), func() *e { return &e{l: rate.NewLimiter(rate.Limit(cl.opts.Limit), cl.opts.Burst)} })
	e.m.Lock()
	e.lastSeen = now
	ok := e.l.AllowN(now, n)
	e.m.Unlock()
	return ok
}

// Stop gc goroutine.
// Do not use this limiter once it was closed.
// Always return nil.
func (cl *ClientLimiter) Close() error {
	cl.closeOnce.Do(func() { close(cl.closeNotify) })
	return nil
}

func (cl *ClientLimiter) mask(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, cl.opts.V4Mask).Masked().Addr()
	}
	if addr.Is6() {
		return netip.PrefixFrom(addr, cl.opts.V6Mask).Masked().Addr()
	}
	return netip.Addr{}
}

func (cl *ClientLimiter) gcLoop() {
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-cl.closeNotify:
			return
		case <-ticker.C:
			cl.gc()
		}
	}
}

func (cl *ClientLimiter) gc() {
	ddl := time.Now().Add(-entryTtl)
	cl.m.Range(func(key netip.Addr, value *e) bool {
		value.m.Lock()
		lastSeen := value.lastSeen
		value.m.Unlock()
		if lastSeen.Before(ddl) {
			cl.m.Delete(key)
		}
		return true
	})
}
