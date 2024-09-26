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

var (
	ErrUpstreamOffline = errors.New("upstream is currently offline")
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
	standalonePing chan struct{} // not nil, no buffer

	hcLock         sync.Mutex
	continuousErr  int
	offline        bool
	offlineTime    time.Time
	cancelPingLoop context.CancelFunc

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
		standalonePing: make(chan struct{}),

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
	if uw.HcEnabled() && uw.HcOffline() {
		uw.HcTryStartPing()
		return nil, ErrUpstreamOffline
	}
	r, err := uw.exchange(ctx, q, m)
	if uw.HcEnabled() {
		if err != nil {
			uw.hcFailed()
		} else {
			uw.hcSucceed()
		}
	}
	return r, err
}

func (uw *UpstreamWrapper) exchange(ctx context.Context, q *QueryCtx, m *dnsmsg.Msg) (*dnsmsg.Msg, error) {
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

// Is upstream currently offline.
// Always return false if health check is disabled.
func (b *UpstreamWrapper) HcOffline() bool {
	if !b.HcEnabled() {
		return false
	}

	b.hcLock.Lock()
	defer b.hcLock.Unlock()
	return b.offline
}

// Notify the health check that the upstream has a successful query.
// Will reset the error counter, stop ongoing ping checks, and notify load
// balancers to rebuild their index.
func (b *UpstreamWrapper) hcSucceed() {
	b.hcLock.Lock()
	b.continuousErr = 0
	prevOffline := b.offline
	b.offline = false
	prevOfflineTime := b.offlineTime
	b.offlineTime = time.Time{}
	if b.cancelPingLoop != nil {
		b.cancelPingLoop()
		b.cancelPingLoop = nil
	}
	b.hcLock.Unlock()

	if prevOffline { // offline -> online
		b.logger.Info().Dur("offline_dur", time.Since(prevOfflineTime)).Msg("upstream online")
		b.hcRebuildLbsIdx()
	}
}

// Notify health check the upstream hcFailed once.
// May trigger offline status if condition meets.
func (b *UpstreamWrapper) hcFailed() {
	b.hcLock.Lock()
	b.continuousErr++
	if !b.offline && b.continuousErr >= b.maxFails {
		b.offline = true
		b.offlineTime = time.Now()
		ctx, cancel := context.WithCancel(b.ctx)
		b.cancelPingLoop = cancel
		b.hcLock.Unlock()
		go func() {
			b.logger.Error().Msg("upstream offline")
			b.hcRebuildLbsIdx()
			b.hcOfflinePingLoop(ctx)
		}()
		return
	}
	b.hcLock.Unlock()
}

// Try to start a health check ping asynchronously if upstream is offline.
// This is useful if caller want trigger the ping test more frequently.
// e.g. After query failed.
// 5s minimal ping interval limit applied.
func (b *UpstreamWrapper) HcTryStartPing() {
	select {
	case b.standalonePing <- struct{}{}:
	default:
	}
}

// Stop if ping succeed or ctx canceled
func (b *UpstreamWrapper) hcOfflinePingLoop(ctx context.Context) {
	const sdPingMinimalInterval = time.Second * 5

	b.logger.Debug().Msg("health check ping loop started")

	t := time.NewTimer(time.Second)
	defer t.Stop()
	var latestSdPing time.Time
	for i := 0; ; i++ {
	again:
		standalone := false
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			b.logger.Debug().Err(err).Msg("health check ping loop canceled")
			return
		case <-b.standalonePing:
			now := time.Now()
			if now.Sub(latestSdPing) < sdPingMinimalInterval {
				goto again
			}
			standalone = true
			latestSdPing = now
		case <-t.C:
		}
		b.logger.Debug().Int("attempt_id", i).Bool("standalone", standalone).Msg("health check ping started")
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		err := b.Ping(ctx)
		cancel()
		if err == nil {
			b.logger.Info().Int("attempt_id", i).Dur("latency", time.Since(start)).Msg("health check ping succeed")
			b.hcSucceed()
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
		b.logger.Warn().Int("attempt_id", i).Dur("elapsed", time.Since(start)).Dur("next_scheduled_ping", interval).Err(err).Msg("health check ping failed")
	}
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

// Must called outside b.hcLock.
// LoadBalancer will call b.HcOffline() which require b.hcLock.
func (b *UpstreamWrapper) hcRebuildLbsIdx() {
	b.lbsLock.Lock()
	defer b.lbsLock.Unlock()
	for lb := range b.lbs {
		lb.buildIdx()
	}
}
