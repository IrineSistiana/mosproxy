package router

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/cespare/xxhash/v2"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

type LoadBalancer struct {
	tag      string
	logger   *zerolog.Logger
	e        []*lbBackend                               // not zero
	simpleFn func(s *lbSampler, q *QueryCtx) *lbBackend // simple from sampler, may return nil if no backend is available

	idxM    sync.Mutex
	sampler atomic.Pointer[lbSampler]
}

func (r *Router) initLoadBalancer(cfg *LoadBalancerConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("empty tag")
	}

	lb := new(LoadBalancer)
	lb.tag = cfg.Tag
	lb.logger = r.subLoggerForLb(cfg.Tag)

	switch cfg.Method {
	case "", "random":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *lbBackend {
			return s.simple(rand.Int())
		}
	case "fall_through":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *lbBackend {
			for _, b := range s.bs {
				if b.rateLimiter == nil {
					return b
				} else if b.rateLimiter.Allow() {
					return b
				}
			}
			return nil
		}
	case "qname_hash":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *lbBackend {
			h := xxhash.Sum64(q.Question.Name.Data())
			return s.simple(int(h))
		}
	case "client_ip_hash":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *lbBackend {
			if q.RemoteAddr.IsValid() {
				b := q.RemoteAddr.Addr().As16()
				h := xxhash.Sum64(b[:])
				return s.simple(int(h))
			}
			return s.simple(rand.Int())
		}
	default:
		return fmt.Errorf("unknown load balance method [%s]", cfg.Method)
	}

	err := r.initLoadBalancerBackends(lb, cfg.Backends)
	if err != nil {
		return fmt.Errorf("failed to init backend, %w", err)
	}
	r.loadBalancers[cfg.Tag] = lb
	return nil
}

func (r *Router) initLoadBalancerBackends(lb *LoadBalancer, backends []LoadBalancerBackendConfig) error {
	for i, cfg := range backends {
		err := r.initLbBackend(lb, cfg)
		if err != nil {
			return fmt.Errorf("failed to init backend #%d, %w", i, err)
		}
	}
	if len(lb.e) == 0 {
		return errors.New("zero backend")
	}
	lb.buildIdx()
	return nil
}

func (lb *LoadBalancer) buildIdx() {
	s := &lbSampler{
		bs: make([]*lbBackend, 0, len(lb.e)),
		wa: make([]int, 0, len(lb.e)),
	}
	offline := make([]string, 0, len(lb.e))

	lb.idxM.Lock()
	ws := 0
	for _, b := range lb.e {
		if b.u.HcOffline() {
			offline = append(offline, b.u.Tag())
			continue
		}
		ws += b.weight
		s.bs = append(s.bs, b)
		s.wa = append(s.wa, ws)
	}
	lb.sampler.Store(s)
	lb.idxM.Unlock()

	online := make([]string, 0, len(s.bs))
	for _, b := range s.bs {
		online = append(online, b.u.Tag())
	}
	lb.logger.Info().
		Strs("online", online).
		Strs("offline", offline).
		Msg("simpler idx rebuilt")
}

func (lb *LoadBalancer) Tag() string { return lb.tag }

func (lb *LoadBalancer) Exchange(ctx context.Context, q *QueryCtx, m *dnsmsg.Msg) error {
	s := lb.sampler.Load()
	b, zero := s.fastPath()
	if zero {
		// Try to start a ping test in a random upstream.
		// Hope some upstreams may have recovered already.
		lb.e[rand.IntN(len(lb.e))].u.HcTryStartPing()
		return errors.New("all backends are offline")
	}
	if b == nil {
		b = lb.simpleFn(s, q)
	}
	if b == nil {
		return errors.New("no backend available")
	}
	return b.u.Exchange(ctx, q, m)
}

// Unregister the LoadBalancer from UpstreamWrapper.
// Dose not close the UpstreamWrapper.
func (lb *LoadBalancer) close() {
	for _, lbb := range lb.e {
		lbb.u.unRegLb(lb)
	}
}

type lbSampler struct {
	wa []int
	bs []*lbBackend
}

func (s *lbSampler) fastPath() (one *lbBackend, zero bool) {
	if len(s.bs) == 0 {
		return nil, true
	}
	if len(s.bs) == 1 {
		return s.bs[0], false
	}
	return nil, false
}

// return nil if no element in s.
func (s *lbSampler) simple(n int) *lbBackend {
	l := len(s.wa)
	if l == 0 {
		return nil
	}
	if l == 1 {
		return s.bs[0]
	}

	r := s.wa[l-1]
	n = n % r
	if n < 0 {
		n = -n
	}
	i, ok := slices.BinarySearch(s.wa, n)
	if ok {
		i++
	}
	i = min(i, l-1)
	return s.bs[i]
}

type lbBackend struct {
	u           *UpstreamWrapper
	weight      int           // not zero
	rateLimiter *rate.Limiter // nil if not configured
}

func (r *Router) initLbBackend(lb *LoadBalancer, cfg LoadBalancerBackendConfig) error {
	u := r.upstreams[cfg.Tag]
	if u == nil {
		return fmt.Errorf("unknown upstream tag [%s]", cfg.Tag)
	}
	if cfg.Weight < 0 { // Disabled backend.
		return nil
	}
	lbb := &lbBackend{
		u:      u,
		weight: defaultIfELZero(cfg.Weight, 1),
	}
	if cfg.QPS > 0 {
		lbb.rateLimiter = rate.NewLimiter(rate.Limit(cfg.QPS), cfg.QPS)
	}
	u.regLb(lb)
	lb.e = append(lb.e, lbb)
	return nil
}
