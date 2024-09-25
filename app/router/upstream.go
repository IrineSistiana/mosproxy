package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/upstream"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

func (r *Router) initUpstream(cfg *UpstreamConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("missing tag")
	}
	if _, dup := r.upstreams[cfg.Tag]; dup {
		return fmt.Errorf("dup tag [%s]", cfg.Tag)
	}
	if len(cfg.Addr) == 0 {
		return errors.New("missing addr")
	}

	tlsConfig, err := makeTlsConfig(&cfg.Tls, false)
	if err != nil {
		return fmt.Errorf("failed to init tls config, %w", err)
	}

	controlOpts := cfg.Socket
	controlOpts._TCP_USER_TIMEOUT = 5000 // 5s
	logger := r.subLoggerForUpstream(cfg.Tag)
	opt := upstream.Opt{
		DialAddr:  cfg.DialAddr,
		Logger:    logger,
		TLSConfig: tlsConfig,
		Control:   controlSocket(controlOpts),
	}
	u, err := upstream.NewUpstream(cfg.Addr, opt)
	if err != nil {
		return fmt.Errorf("failed to init upstream. %w", err)
	}

	w := r.wrapUpstream(cfg.Tag, u, logger, cfg.HealthCheck)
	if err := w.RegisterMetricsTo(r.metricsReg); err != nil {
		return fmt.Errorf("failed to register metrics, %w", err)
	}
	r.upstreams[cfg.Tag] = w
	return nil
}

type Upstream interface {
	Exchange(ctx context.Context, q *QueryCtx, m *dnsmsg.Msg) (*dnsmsg.Msg, error)
}

// Wrapper for upstream.Upstream, with tag info and metrics.
type UpstreamWrapper struct {
	r      *Router
	tag    string
	u      upstream.Upstream
	logger *zerolog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	// hc
	maxFails       int
	hcPingInterval time.Duration // not zero

	hcLock     sync.Mutex
	errCounter int
	offline    bool

	lbsLock sync.Mutex
	lbs     map[*LoadBalancer]struct{} // lbs that use this upstream as backend

	queryTotal      prometheus.Counter
	errTotal        prometheus.Counter
	thread          prometheus.Gauge
	hcOffline       prometheus.GaugeFunc
	responseLatency prometheus.Histogram
}

func (r *Router) wrapUpstream(tag string, u upstream.Upstream, logger *zerolog.Logger, hcCfg HealthCheckConfig) *UpstreamWrapper {
	ctx, cancel := context.WithCancel(r.ctx)
	cb := map[string]string{"upstream": tag}
	uw := &UpstreamWrapper{
		r:      r,
		tag:    tag,
		u:      u,
		logger: logger,

		ctx:    ctx,
		cancel: cancel,

		maxFails:       hcCfg.MaxFails,
		hcPingInterval: time.Duration(defaultIfELZero(hcCfg.PingInterval, 120)) * time.Second,

		lbs: make(map[*LoadBalancer]struct{}),

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "upstream_query_total",
			Help:        "The total number of queries processed by this upstream",
			ConstLabels: cb,
		}),
		errTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "upstream_err_total",
			Help:        "The total number of queries failed",
			ConstLabels: cb,
		}),
		thread: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "upstream_thread",
			Help:        "The number of threads (queries) that are currently being processed",
			ConstLabels: cb,
		}),
		responseLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "upstream_response_latency_millisecond",
			Help:        "The response latency in millisecond",
			Buckets:     []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
			ConstLabels: cb,
		}),
	}

	uw.hcOffline = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "upstream_health_check_offline",
		Help:        "Is upstream currently offline (Report by health check)(1: offline)",
		ConstLabels: cb,
	}, func() float64 {
		if uw.HcOffline() {
			return 1
		}
		return 0
	})
	return uw
}

func (uw *UpstreamWrapper) RegisterMetricsTo(r prometheus.Registerer) error {
	return RegMetrics(r, uw.queryTotal, uw.errTotal, uw.thread, uw.hcOffline, uw.responseLatency)
}

func (uw *UpstreamWrapper) Tag() string {
	return uw.tag
}

func (uw *UpstreamWrapper) Ping(ctx context.Context) error {
	m := dnsmsg.NewMsg()
	defer dnsmsg.ReleaseMsg(m)

	q := dnsmsg.NewQuestion()
	q.Name.Finish()
	q.Class = dnsmsg.ClassINET
	q.Type = dnsmsg.TypeNS
	m.Questions = append(m.Questions, q)

	_, err := uw.u.ExchangeContext(ctx, m)
	return err
}

func (uw *UpstreamWrapper) Exchange(ctx context.Context, q *QueryCtx, m *dnsmsg.Msg) (*dnsmsg.Msg, error) {
	r := uw.r
	if r.opt.Log.TraceMsgs {
		r.debugLogMsg(q, m, uw.tag, "sending query to upstream")
	}

	uw.queryTotal.Inc()
	start := time.Now()
	uw.thread.Inc()
	resp, err := uw.u.ExchangeContext(ctx, m)
	uw.thread.Dec()
	if err != nil {
		uw.errTotal.Inc()
		r.logger.Warn().
			Dict("query", q.LogQuery()).
			Err(err).
			Str("upstream", uw.tag).
			Msg("failed to forward query")
	} else {
		uw.responseLatency.Observe(float64(time.Since(start).Milliseconds()))
		if r.opt.Log.TraceMsgs {
			r.debugLogMsg(q, resp, uw.tag, "response received from upstream")
		}
		q.Trace.Upstream = uw.tag
	}
	return resp, err
}

func (uw *UpstreamWrapper) close() error {
	uw.cancel()
	return uw.u.Close()
}

func (b *UpstreamWrapper) HcEnabled() bool {
	return b.maxFails > 0
}

func (b *UpstreamWrapper) regLb(lb *LoadBalancer) {
	b.lbsLock.Lock()
	defer b.lbsLock.Unlock()
	b.lbs[lb] = struct{}{}
}

func (b *UpstreamWrapper) unRegLb(lb *LoadBalancer) {
	b.lbsLock.Lock()
	defer b.lbsLock.Unlock()
	delete(b.lbs, lb)
}

func (b *UpstreamWrapper) hcRebuildLbsIdx() {
	b.lbsLock.Lock()
	defer b.lbsLock.Unlock()
	for lb := range b.lbs {
		lb.buildIdx()
	}
}

// Note: Always return false if health check is disabled.
func (b *UpstreamWrapper) HcOffline() bool {
	if !b.HcEnabled() {
		return false
	}

	b.hcLock.Lock()
	defer b.hcLock.Unlock()
	return b.offline
}

func (b *UpstreamWrapper) Succeed() {
	if !b.HcEnabled() {
		return
	}

	b.hcLock.Lock()
	b.errCounter = 0
	b.hcLock.Unlock()
}

func (b *UpstreamWrapper) Failed() {
	if !b.HcEnabled() {
		return
	}

	var wentOffline bool
	b.hcLock.Lock()
	b.errCounter++
	if !b.offline {
		// Query failed to many times continuously || No query was successful during a period of time.
		if b.errCounter >= b.maxFails {
			b.offline = true
			wentOffline = true
		}
	}
	b.hcLock.Unlock()

	if wentOffline {
		b.logger.Error().Msg("upstream offline")
		offlineTime := time.Now()
		b.hcRebuildLbsIdx()
		go func() {
			defer func() {
				b.hcLock.Lock()
				b.errCounter = 0
				b.offline = false
				b.hcLock.Unlock()
				b.logger.Info().Dur("offline_dur", time.Since(offlineTime)).Msg("backend online")
				b.hcRebuildLbsIdx()
			}()
			b.healthCheckLoopTillOnline()
		}()
	}
}

func (b *UpstreamWrapper) healthCheckLoopTillOnline() {
	e := b.logger.Debug()
	if e != nil {
		e.Msg("health check loop started")
	}

	t := time.NewTimer(time.Second)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-b.ctx.Done():
			return
		case <-t.C:
			e := b.logger.Debug()
			if e != nil {
				e.Int("attempt_id", i).Msg("health check started")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
			err := b.Ping(ctx)
			cancel()
			if err == nil {
				e := b.logger.Debug()
				if e != nil {
					e.Int("attempt_id", i).Msg("health check succeed")
				}
				return
			}

			interval := b.hcPingInterval
			if i < 8 {
				fastRecover := (1 << i) * time.Second
				if fastRecover < interval {
					interval = fastRecover
				}
			}
			t.Reset(interval)
			e = b.logger.Debug()
			if e != nil {
				e.Int("attempt_id", i).Dur("next_check", interval).Err(err).Msg("health check failed")
			}
		}
	}
}
