package router

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/upstream"
	"github.com/prometheus/client_golang/prometheus"
)

func (r *router) initUpstream(cfg *UpstreamConfig) error {
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
	opt := upstream.Opt{
		DialAddr:  cfg.DialAddr,
		Logger:    r.subLoggerForUpstream(cfg.Tag),
		TLSConfig: tlsConfig,
		Control:   controlSocket(controlOpts),
	}
	u, err := upstream.NewUpstream(cfg.Addr, opt)
	if err != nil {
		return fmt.Errorf("failed to init upstream. %w", err)
	}

	w := wrapUpstream(cfg.Tag, u)
	if err := w.RegisterMetricsTo(r.metricsReg); err != nil {
		return fmt.Errorf("failed to register metrics, %w", err)
	}
	r.upstreams[cfg.Tag] = w
	return nil
}

type upstreamWrapper struct {
	tag string
	u   upstream.Upstream

	queryTotal      prometheus.Counter
	errTotal        prometheus.Counter
	thread          prometheus.Gauge
	responseLatency prometheus.Histogram
}

func wrapUpstream(tag string, u upstream.Upstream) *upstreamWrapper {
	cb := map[string]string{"upstream": tag}
	return &upstreamWrapper{
		tag: tag,
		u:   u,

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
}

func (uw *upstreamWrapper) RegisterMetricsTo(r prometheus.Registerer) error {
	return regMetrics(r, uw.queryTotal, uw.errTotal, uw.thread, uw.responseLatency)
}

func (uw *upstreamWrapper) Exchange(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	uw.queryTotal.Inc()
	var (
		r   *dnsmsg.Msg
		err error
	)
	start := time.Now()
	uw.thread.Inc()
	r, err = uw.u.ExchangeContext(ctx, m)
	uw.thread.Dec()

	if err != nil {
		uw.errTotal.Inc()
	} else {
		uw.responseLatency.Observe(float64(time.Since(start).Milliseconds()))
	}
	return r, err
}

func (uw *upstreamWrapper) Close() error {
	return uw.u.Close()
}
