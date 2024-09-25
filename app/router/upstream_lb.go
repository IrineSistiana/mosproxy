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
)

type LoadBalancer struct {
	tag      string
	logger   *zerolog.Logger
	e        []*lbBackend
	simpleFn func(s *lbSampler, q *QueryCtx) *UpstreamWrapper

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
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *UpstreamWrapper {
			return s.simple(rand.Int())
		}
	case "qname_hash":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *UpstreamWrapper {
			h := xxhash.Sum64(q.Question.Name.Data())
			return s.simple(int(h))
		}
	case "client_ip_hash":
		lb.simpleFn = func(s *lbSampler, q *QueryCtx) *UpstreamWrapper {
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
		us: make([]*UpstreamWrapper, 0, len(lb.e)),
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
		s.us = append(s.us, b.u)
		s.wa = append(s.wa, ws)
	}
	lb.sampler.Store(s)
	lb.idxM.Unlock()

	online := make([]string, 0, len(s.us))
	for _, u := range s.us {
		online = append(online, u.Tag())
	}
	lb.logger.Info().
		Strs("online", online).
		Strs("offline", offline).
		Msg("simpler idx rebuilt")
}

func (lb *LoadBalancer) Tag() string { return lb.tag }

func (lb *LoadBalancer) Exchange(ctx context.Context, q *QueryCtx, m *dnsmsg.Msg) (*dnsmsg.Msg, error) {
	s := lb.sampler.Load()
	u, zero := s.fastPath()
	if zero {
		return nil, errors.New("all backends are offline")
	}
	if u == nil {
		u = lb.simpleFn(s, q)
	}

	q.Trace.Upstream = u.Tag()
	resp, err := u.Exchange(ctx, q, m)
	if err != nil {
		u.Failed()
	} else {
		u.Succeed()
	}
	return resp, err
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
	us []*UpstreamWrapper
}

func (s *lbSampler) fastPath() (one *UpstreamWrapper, zero bool) {
	if len(s.us) == 0 {
		return nil, true
	}
	if len(s.us) == 1 {
		return s.us[0], false
	}
	return nil, false
}

// return nil if no element in s.
func (s *lbSampler) simple(n int) *UpstreamWrapper {
	l := len(s.wa)
	if l == 0 {
		return nil
	}
	if l == 1 {
		return s.us[0]
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
	return s.us[i]
}

type lbBackend struct {
	u      *UpstreamWrapper
	weight int // not zero
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
	u.regLb(lb)
	lb.e = append(lb.e, lbb)
	return nil
}
