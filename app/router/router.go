package router

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/IrineSistiana/gopool"
	"github.com/IrineSistiana/mosproxy/app"
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	udpSize      = 1200
	queryTimeout = time.Second * 6
)

func init() {
	app.RootCmd().AddCommand(newRouterCmd())
}

func newRouterCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "router",
		Short: "Start the dns router",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			logger := mlog.L()
			b, err := os.ReadFile(cfgPath)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to read config file")
			}

			cfg := new(Config)
			m := make(map[string]any)
			if err := yaml.Unmarshal(b, m); err != nil {
				logger.Fatal().Err(err).Msg("failed to decode yaml config")
			}
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				ErrorUnused: true,
				TagName:     "yaml",
				Result:      cfg,
			})
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to init yaml decoder")
			}
			if err := decoder.Decode(m); err != nil {
				logger.Fatal().Err(err).Msg("failed to decode yaml struct")
			}
			logger.Info().Str("file", cfgPath).Msg("config file loaded")

			r, err := Run(cmd.Context(), cfg)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to start router")
			}

			exitSigChan := make(chan os.Signal, 1)
			signal.Notify(exitSigChan, append([]os.Signal{os.Interrupt}, exitSig...)...)

			select {
			case sig := <-exitSigChan:
				err = fmt.Errorf("signal %s", sig)
				goto shutdown
			case <-r.ctx.Done():
				err = context.Cause(r.ctx)
				goto shutdown
			case fatalErr := <-r.fatalErr:
				logger.Fatal().Err(fatalErr.err).Msg(fatalErr.msg)
			}

		shutdown:
			logger.Info().AnErr("cause", err).Msg("router exiting")
			r.Close(err)
			logger.Info().Msg("router exited, context closed")
			os.Exit(0)
		},
	}
	c.Flags().StringVarP(&cfgPath, "config", "c", "config.yaml", "path of the config file")

	genConfigCmd := &cobra.Command{
		Use:   "gen-config",
		Short: "Generate a config template",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			genConfigTemplate(args[0])
		},
	}
	c.AddCommand(genConfigCmd)
	return c
}

type Router struct {
	opt *Config

	// not nil
	ctx        context.Context
	cancel     context.CancelCauseFunc
	logger     *zerolog.Logger
	metricsReg *prometheus.Registry
	limiter    *resourceLimiter
	fatalErr   chan fatalErr
	prefetch   *prefetchCtl
	bJobPool   *gopool.Pool[blockingJobArgs] // pool for blocking jobs

	// metrics
	queryTotal         prometheus.Counter
	queryCacheHitTotal prometheus.Counter
	prefetchTotal      prometheus.Counter

	closeOnce sync.Once

	// init later
	cache         *cacheCtl // not nil, noop if no backend is configured
	upstreams     map[string]*upstreamWrapper
	domainSets    map[string]*domainmatcher.MixMatcher
	rules         []*rule
	serverClosers []func()
}

type fatalErr struct {
	msg string
	err error
}

func Run(ctx context.Context, cfg *Config) (_ *Router, err error) {
	logger := mlog.L()
	ctx, cancel := context.WithCancelCause(ctx)
	r := &Router{
		opt:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
		metricsReg: newMetricsReg(),
		limiter:    initResourceLimiter(cfg.Limiter),
		fatalErr:   make(chan fatalErr, 1),
		prefetch:   newPrefetchCtl(),
		bJobPool:   gopool.NewPool[blockingJobArgs](),

		upstreams:  make(map[string]*upstreamWrapper),
		domainSets: make(map[string]*domainmatcher.MixMatcher),

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "The total number of client queries",
		}),
		queryCacheHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_cache_hit_total",
			Help: "The total number of client queries that hit the cache",
		}),
		prefetchTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "prefetch_total",
			Help: "The total number of prefetched queries",
		}),
	}

	// close r if failed to init
	defer func() {
		if err != nil {
			r.Close(err)
		}
	}()

	err = regMetrics(r.metricsReg,
		r.queryTotal,
		r.queryCacheHitTotal,
		r.prefetchTotal,
	)
	if err != nil {
		err = fmt.Errorf("failed to reg prometheus metrics, %w", err)
		return
	}

	// start metrics endpoint
	if addr := cfg.Metrics.Addr; len(addr) > 0 {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			err = fmt.Errorf("failed to start prometheus metrics endpoint server, %w", err)
			return nil, err
		}

		logger.Info().Stringer("addr", l.Addr()).Msg("metrics endpoint server started")

		s := http.Server{
			Handler: promhttp.HandlerFor(r.metricsReg, promhttp.HandlerOpts{}),
		}
		r.serverClosers = append(r.serverClosers, func() { s.Close() })
		go func() {
			err := s.Serve(l)
			if !errors.Is(err, http.ErrServerClosed) {
				r.fatal("metrics endpoint exited", err)
			}
		}()
	}

	// init upstreams
	for i, upstreamCfg := range cfg.Upstreams {
		err := r.initUpstream(&upstreamCfg)
		if err != nil {
			err = fmt.Errorf("failed to init upstream #%d, %w", i, err)
			return nil, err
		}
	}

	// init domain sets
	for i, domainSet := range cfg.DomainSets {
		err := r.loadDomainSet(&domainSet)
		if err != nil {
			err = fmt.Errorf("failed to init domain set #%d, %w", i, err)
			return nil, err
		}
	}

	// init rules
	for i, ruleCfg := range cfg.Rules {
		ru, err := r.loadRule(&ruleCfg)
		if err != nil {
			err = fmt.Errorf("failed to load rule #%d, %w", i, err)
			return nil, err
		}
		r.rules = append(r.rules, ru)
	}

	// init cache
	cache, err := r.initCache(&cfg.Cache)
	if err != nil {
		err = fmt.Errorf("failed to init cache, %w", err)
		return
	}
	r.cache = cache

	// start servers
	for i, serverCfg := range cfg.Servers {
		closer, err := r.startServer(&serverCfg)
		r.serverClosers = append(r.serverClosers, closer)
		if err != nil {
			err = fmt.Errorf("failed to start server #%d, %w", i, err)
			return nil, err
		}
	}

	runtime.GC()
	debug.FreeOSMemory()
	logger.Info().Msg("router is up and running")

	return r, nil
}

func (r *Router) fatal(msg string, err error) {
	select {
	case r.fatalErr <- fatalErr{msg: msg, err: err}:
	default:
	}
}

func (r *Router) Close(err error) {
	r.closeOnce.Do(func() {
		r.closeImpl(err)
	})
}

// Will only be called when router failed to init (in the same goroutine)
// or after router is started (from other goroutines).
func (r *Router) closeImpl(err error) {
	r.cancel(err)
	r.limiter.Close()
	for _, u := range r.upstreams {
		u.u.Close()
	}
	if r.cache != nil {
		r.cache.Close()
	}
	for _, f := range r.serverClosers {
		f()
	}
}

func makeEmptyRespM(m *dnsmsg.Msg, rcode dnsmsg.RCode) *dnsmsg.Msg {
	resp := dnsmsg.NewMsg()
	resp.RCode = rcode
	for _, q := range m.Questions {
		resp.Questions = append(resp.Questions, q.Copy())
		break // only return one question. Avoid malicious queries.
	}
	postProcessResp(getQueryInfo(m), resp)
	return resp
}

func mustHaveEmptyRespForQueryB(q *dnsmsg.Msg, rcode dnsmsg.RCode, tcp bool, size int) pool.Buffer {
	resp := makeEmptyRespM(q, rcode)
	b := mustHaveRespB(resp, tcp, size)
	dnsmsg.ReleaseMsg(resp)
	return b
}

// If resp must not be nil.
// If tcp is true, size is ignored.
func mustHaveRespB(resp *dnsmsg.Msg, tcp bool, size int) pool.Buffer {
	var b pool.Buffer
	var err error

	if tcp {
		b, err = packRespTCP(resp, true)
	} else {
		b, err = packResp(resp, true, size)
	}
	if err == nil {
		return b
	}

	mlog.L().Error().Err(err).Msg("internal err: failed to pack dns msg")

	// Failed to pack resp.
	// Try only pack header.
	var body []byte
	if tcp {
		b = pool.GetBuf(2 + 12)
		body = b[2:]
	} else {
		b = pool.GetBuf(12)
		body = b
	}

	hdr := resp.Header
	hdr.RCode = dnsmsg.RCodeServerFailure
	id, bits := hdr.Pack()
	binary.BigEndian.PutUint16(body[0:], id)
	binary.BigEndian.PutUint16(body[2:], bits)
	return b
}

func (r *Router) asyncSingleFlightPrefetch(q qCtx, remoteAddr netip.Addr, u *upstreamWrapper) {
	key := r.cache.keyForPrefetch(q.q, remoteAddr)
	if ok := r.prefetch.reserve(key); !ok {
		return
	}
	qCopy := qCtx{q: q.q.Copy(), qMeta: q.qMeta, qInfo: q.qInfo}
	go func() {
		defer dnsmsg.ReleaseQuestion(qCopy.q)
		r.doPrefetch(qCopy, remoteAddr, u)
		r.prefetch.done(key)
	}()
}

func (r *Router) doPrefetch(q qCtx, remoteAddr netip.Addr, u *upstreamWrapper) {
	r.logger.Debug().Object("query", (*qLogObj)(q.q)).Str("upstream", u.tag).Msg("prefetching cache")

	ctx, cancel := context.WithTimeout(r.ctx, prefetchTimeout)
	defer cancel()
	resp, err := r.forward(ctx, q, remoteAddr, u)
	if err != nil {
		r.logger.Warn().Object("query", (*qLogObj)(q.q)).Str("upstream", u.tag).Err(err).
			Msg("failed to prefetch")
		return
	}
	r.prefetchTotal.Inc()
	r.cache.Store(q.q, remoteAddr, resp)
}

// Forward query to upstream and return its response.
// It will remove the EDNS0 Options from response.
func (r *Router) forward(ctx context.Context,
	q qCtx,
	remoteAddr netip.Addr,
	upstream *upstreamWrapper,
) (*dnsmsg.Msg, error) {
	resp, err := r._forward(ctx, q, remoteAddr, upstream)
	if resp != nil {
		dnsmsg.RemoveEDNS0(resp)
	}
	return resp, err
}

func (r *Router) _forward(
	ctx context.Context,
	q qCtx,
	remoteAddr netip.Addr,
	upstream *upstreamWrapper,
) (*dnsmsg.Msg, error) {
	queryMsg := r.makeQueryMsg(q.q, remoteAddr)
	defer dnsmsg.ReleaseMsg(queryMsg)

	resp, err := middlewareImpl().PreForwarding(ctx, queryMsg, q.qMeta, q.qInfo)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		return resp, nil
	}

	queryWire, err := packResp(queryMsg, false, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to pack req, %w", err)
	}
	defer pool.ReleaseBuf(queryWire)

	resp, err = upstream.Exchange(ctx, queryWire)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange, %w", err)
	}
	return resp, nil
}

func makeEmptyRespMQ(q *dnsmsg.Question, rcode uint16) *dnsmsg.Msg {
	resp := dnsmsg.NewMsg()
	resp.Header.RCode = dnsmsg.RCode(rcode)
	resp.Questions = append(resp.Questions, q.Copy())
	return resp
}

func (r *Router) makeQueryMsg(q *dnsmsg.Question, remoteAddr netip.Addr) *dnsmsg.Msg {
	m := dnsmsg.NewMsg()
	m.Header.RecursionDesired = true
	m.Questions = append(m.Questions, q.Copy())

	opt := newEDNS0(udpSize)
	if r.opt.ECS.Enabled && remoteAddr.IsValid() {
		opt.Data = makeEdns0ClientSubnetReqOpt(remoteAddr)
	}
	m.Additionals = append(m.Additionals, opt)
	return m
}

func (r *Router) subLogger(modName string) *zerolog.Logger {
	l := r.logger.With().Str("module", modName).Logger()
	return &l
}

func (r *Router) subLoggerForServer(modName string, tag string) *zerolog.Logger {
	ctx := r.logger.With().Str("module", modName)
	if len(tag) > 0 {
		ctx = ctx.Str("server_tag", tag)
	}
	l := ctx.Logger()
	return &l
}

func (r *Router) subLoggerForUpstream(tag string) *zerolog.Logger {
	ctx := r.logger.With().Str("module", "upstream")
	if len(tag) > 0 {
		ctx = ctx.Str("upstream_tag", tag)
	}
	l := ctx.Logger()
	return &l
}

// Helper func.
func (r *Router) limiterAllowN(addr netip.Addr, n int) error {
	return r.limiter.AllowN(addr, n)
}
