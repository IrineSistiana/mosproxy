package router

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/app"
	"github.com/IrineSistiana/mosproxy/app/router/loader"
	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
	"github.com/IrineSistiana/mosproxy/internal/ipmarker"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
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
	fatalErr   chan fatalErr
	prefetch   *prefetchCtl

	// metrics
	queryTotal         prometheus.Counter
	queryCacheHitTotal prometheus.Counter
	prefetchTotal      prometheus.Counter

	closeOnce sync.Once

	// init later
	ecsZone          *loader.Loader[string, ipmarker.IpMarker]       // nil if not configured
	ecsZoneOverwrite *loader.Loader[string, map[string]netip.Prefix] // nil if not configured
	cache            *cacheCtl                                       // not nil, noop if no backend is configured
	upstreams        map[string]*upstreamWrapper
	domainSets       map[string]*loader.Loader[[]string, domainmatcher.Matcher]
	rules            []*rule
	serverClosers    []func()

	reloading atomic.Uint32 // 1 = true
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
		fatalErr:   make(chan fatalErr, 1),
		prefetch:   newPrefetchCtl(),

		upstreams:  make(map[string]*upstreamWrapper),
		domainSets: make(map[string]*loader.Loader[[]string, domainmatcher.Matcher]),

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

	err = r.initApiServer(&cfg.API)
	if err != nil {
		err = fmt.Errorf("failed to start api server, %w", err)
		return
	}

	// init upstreams
	for i, upstreamCfg := range cfg.Upstreams {
		err := r.initUpstream(&upstreamCfg)
		if err != nil {
			err = fmt.Errorf("failed to init upstream #%d, %w", i, err)
			return nil, err
		}
	}

	// init ecs zone
	if len(cfg.ECS.IpZone) > 0 {
		err = r.loadEcsZone(cfg.ECS.IpZone)
		if err != nil {
			err = fmt.Errorf("failed to load ecs zone file, %w", err)
			return
		}
	} else {
		if cfg.ECS.Enabled && (cfg.Cache.MemSize > 0 || len(cfg.Cache.Redis) > 0) {
			r.logger.Warn().Msg("ECS is enabled. But no zone file is configured. Cache WILL NOT work as expected as a geo based cache.")
		}
	}

	// init ecs overwrite rules
	if fp := cfg.ECS.ZoneOverwrite; len(fp) > 0 {
		err = r.loadZoneEcs(fp)
		if err != nil {
			err = fmt.Errorf("failed to zone ecs file, %w", err)
			return
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
	return resp
}

func (r *Router) asyncSingleFlightPrefetch(key []byte, q *QueryCtx, u *upstreamWrapper) {
	uk := r.prefetch.Key(key)
	if ok := r.prefetch.Reserve(uk); !ok {
		return
	}
	keyCopy := pool.CopyBuf(key)
	qCopy := q.Copy()
	go func() {
		defer pool.ReleaseBuf(keyCopy)
		defer ReleaseQueryCtx(qCopy)
		defer r.prefetch.Done(uk)
		r.doPrefetch(keyCopy, qCopy, u)
	}()
}

func (r *Router) doPrefetch(key []byte, q *QueryCtx, u *upstreamWrapper) {
	e := r.logger.Debug()
	if e != nil {
		e.Dict("query", q.LogBasic()).Str("upstream", u.tag).Msg("prefetching cache")
	}

	ctx, cancel := context.WithTimeout(r.ctx, prefetchTimeout)
	defer cancel()
	err := r.forward(ctx, q, u)
	if err != nil {
		r.logger.Warn().Dict("query", q.LogBasic()).Str("upstream", u.tag).Err(err).
			Msg("failed to prefetch")
		return
	}
	r.prefetchTotal.Inc()
	r.cache.Store(key, q)
}

// Forward query to upstream and set the response.
// Will remove edns0 from resp.
func (r *Router) forward(
	ctx context.Context,
	q *QueryCtx,
	upstream *upstreamWrapper,
) error {
	queryMsg := r.makeQueryMsg(q)
	defer dnsmsg.ReleaseMsg(queryMsg)

	if r.opt.Log.TraceMsgs {
		r.debugLogMsg(q, queryMsg, "sending query to upstream")
	}

	resp, err := upstream.Exchange(ctx, queryMsg)
	if err != nil {
		return fmt.Errorf("failed to exchange, %w", err)
	}

	if r.opt.Log.TraceMsgs {
		r.debugLogMsg(q, resp, "response received from upstream")
	}

	dnsmsg.RemoveEDNS0(resp)
	q.Resp = resp
	return nil
}

func setEmptyRespMQ(q *QueryCtx, rcode dnsmsg.RCode) {
	if q.Resp != nil {
		dnsmsg.ReleaseMsg(q.Resp)
		q.Resp = nil
	}
	resp := dnsmsg.NewMsg()
	resp.RCode = rcode
	resp.Questions = append(resp.Questions, q.Question.Copy())
	q.Resp = resp
}

func (r *Router) makeQueryMsg(q *QueryCtx) *dnsmsg.Msg {
	m := dnsmsg.NewMsg()
	m.Header.RecursionDesired = true
	m.Questions = append(m.Questions, q.Question.Copy())

	opt := newEDNS0(udpSize)
	if ecs := q.ECS2Upstream; ecs.IsValid() {
		addr := ecs.Addr()
		if !addr.IsPrivate() && addr.IsGlobalUnicast() {
			opt.Data = makeEdns0ClientSubnetReqOpt(ecs)
		}
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
