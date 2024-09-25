package router

import (
	"context"
	"fmt"
	"io"
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

			r, err := Run(cfg)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to start router")
			}

			exitSigChan := make(chan os.Signal, 1)
			signal.Notify(exitSigChan, append([]os.Signal{os.Interrupt}, exitSig...)...)

			var shutdownLog *zerolog.Event
			select {
			case sig := <-exitSigChan:
				err = fmt.Errorf("signal %s", sig)
				shutdownLog = logger.Info()
				goto shutdown
			case <-r.ctx.Done():
				err = context.Cause(r.ctx)
				shutdownLog = logger.Error()
				goto shutdown
			}

		shutdown:
			shutdownLog.AnErr("cause", err).Msg("router exiting")
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
	prefetchSf *prefetchCtl

	// metrics
	queryTotal         prometheus.Counter
	queryCacheHitTotal prometheus.Counter
	prefetchTotal      prometheus.Counter

	closeOnce sync.Once

	// init later
	ecsZone          *loader.Loader[string, ipmarker.IpMarker]                  // nil if not configured
	ecsZoneOverwrite *loader.Loader[string, ECSZoneOverWrite]                   // nil if not configured
	cache            *CacheCtl                                                  // not nil, noop if no backend is configured
	upstreams        map[string]*UpstreamWrapper                                // not nil
	loadBalancers    map[string]*LoadBalancer                                   // not nil
	domainSets       map[string]*loader.Loader[[]string, domainmatcher.Matcher] // not nil
	rules            []*rule
	middlewares      []Handler // nil if no middleware
	serverClosers    []func()

	reloading atomic.Uint32 // 1 = true
}

func Run(cfg *Config) (_ *Router, err error) {
	logger := mlog.L()
	ctx, cancel := context.WithCancelCause(context.Background())
	r := &Router{
		opt:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
		metricsReg: newMetricsReg(),
		prefetchSf: newPrefetchCtl(),

		upstreams:     make(map[string]*UpstreamWrapper),
		loadBalancers: make(map[string]*LoadBalancer),
		domainSets:    make(map[string]*loader.Loader[[]string, domainmatcher.Matcher]),

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

	err = RegMetrics(r.metricsReg,
		r.queryTotal,
		r.queryCacheHitTotal,
		r.prefetchTotal,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reg prometheus metrics, %w", err)
	}

	err = r.initApiServer(&cfg.API)
	if err != nil {
		return nil, fmt.Errorf("failed to start api server, %w", err)
	}

	// init upstreams
	for i, upstreamCfg := range cfg.Upstreams {
		err := r.initUpstream(&upstreamCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream #%d, %w", i, err)
		}
	}

	// init load balancers
	for i, lbCfg := range cfg.LoadBalancers {
		err := r.initLoadBalancer(&lbCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to init load balancer #%d, %w", i, err)
		}
	}

	// init ecs zone
	if len(cfg.ECS.IpZone) > 0 {
		err = r.loadEcsZone(cfg.ECS.IpZone)
		if err != nil {
			return nil, fmt.Errorf("failed to load ecs zone file, %w", err)
		}
	} else {
		if cfg.ECS.Enabled && (cfg.Cache.MemSize > 0 || len(cfg.Cache.Redis) > 0) {
			r.logger.Warn().Msg("ECS is enabled. But no zone file is configured. Cache WILL NOT work as expected as a geo based cache.")
		}
	}

	// init ecs overwrite rules
	if fp := cfg.ECS.ZoneOverwrite; len(fp) > 0 {
		err = r.loadEcsZoneOverwrite(fp)
		if err != nil {
			return nil, fmt.Errorf("failed to zone ecs file, %w", err)
		}
	}

	// init domain sets
	for i, domainSet := range cfg.DomainSets {
		err := r.loadDomainSet(&domainSet)
		if err != nil {
			return nil, fmt.Errorf("failed to init domain set #%d, %w", i, err)
		}
	}

	// init rules
	for i, ruleCfg := range cfg.Rules {
		ru, err := r.loadRule(&ruleCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to load rule #%d, %w", i, err)
		}
		r.rules = append(r.rules, ru)
	}

	// init cache
	cache, err := r.initCache(&cfg.Cache)
	if err != nil {
		return nil, fmt.Errorf("failed to init cache, %w", err)
	}
	r.cache = cache

	// init middlewares
	if len(cfg.Middleware) > 0 {
		err := r.initMiddlewares(cfg.Middleware)
		if err != nil {
			return nil, fmt.Errorf("failed to init middlewares, %w", err)
		}
	}

	// start servers
	for i, serverCfg := range cfg.Servers {
		closer, err := r.startServer(&serverCfg)
		r.serverClosers = append(r.serverClosers, closer)
		if err != nil {
			return nil, fmt.Errorf("failed to start server #%d, %w", i, err)
		}
	}

	runtime.GC()
	debug.FreeOSMemory()
	logger.Info().Msg("router is up and running")

	return r, nil
}

// Context will be canceled then Router being closed.
func (r *Router) Context() context.Context {
	return r.ctx
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
	for _, f := range r.serverClosers {
		f()
	}
	for _, m := range r.middlewares {
		if closer, ok := m.(io.Closer); ok {
			closer.Close()
		}
	}
	for _, u := range r.upstreams {
		u.close()
	}
	for _, lb := range r.loadBalancers {
		lb.close()
	}
	if r.cache!=nil{
		r.cache.close()
	}
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

func (r *Router) subLoggerForLb(tag string) *zerolog.Logger {
	ctx := r.logger.With().Str("module", "load_balancer")
	if len(tag) > 0 {
		ctx = ctx.Str("load_balancer_tag", tag)
	}
	l := ctx.Logger()
	return &l
}

func (r *Router) subLoggerForMiddleware(typ string) *zerolog.Logger {
	ctx := r.logger.With().Str("middleware", typ)
	l := ctx.Logger()
	return &l
}

// Nil if not configured. DO NOT retain the result. It will be replaced
// when router reloaded.
func (r *Router) GetECSZone() *ipmarker.IpMarker {
	if r.ecsZone != nil {
		return r.ecsZone.V()
	}
	return nil
}

// Nil if not configured. DO NOT retain the result. It will be replaced
// when router reloaded.
func (r *Router) GetECSZoneOverwrite() *ECSZoneOverWrite {
	if r.ecsZoneOverwrite != nil {
		return r.ecsZoneOverwrite.V()
	}
	return nil
}

// Nil if not configured.
func (r *Router) GetUpstream(tag string) *UpstreamWrapper {
	return r.upstreams[tag]
}

// Nil if not configured.
func (r *Router) GetLoadBalancer(tag string) *LoadBalancer {
	return r.loadBalancers[tag]
}

// Nil if not configured. DO NOT retain the result. It will be replaced
// when router reloaded.
func (r *Router) GetDomainSet(tag string) *domainmatcher.Matcher {
	loader, ok := r.domainSets[tag]
	if !ok {
		return nil
	}
	return loader.V()
}

func (r *Router) GetCache() *CacheCtl {
	return r.cache
}

func (r *Router) GetMetricsReg() *prometheus.Registry {
	return r.metricsReg
}
