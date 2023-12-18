package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/IrineSistiana/mosproxy/app"
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	udpSize = 1200
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
				logger.Fatal("failed to read config file", zap.Error(err))
			}
			cfg := new(Config)

			m := make(map[string]any)
			if err := yaml.Unmarshal(b, m); err != nil {
				logger.Fatal("failed to decode yaml config", zap.Error(err))
			}
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				ErrorUnused: true,
				TagName:     "yaml",
				Result:      cfg,
			})
			if err != nil {
				logger.Fatal("failed to init yaml decoder", zap.Error(err))
			}
			if err := decoder.Decode(m); err != nil {
				logger.Fatal("failed to decode yaml struct", zap.Error(err))
			}

			logger.Info("config file loaded", zap.String("file", cfgPath))
			run(cmd.Context(), cfg)
		},
	}
	c.Flags().StringVarP(&cfgPath, "config", "c", "config.json", "path of the config file")

	genConfigCmd := &cobra.Command{
		Use:   "gen-config",
		Short: "Generate a config template",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			genConfigTemplate(args[0])
		},
	}
	c.AddCommand(genConfigCmd)
	c.AddCommand(newConvIpMarkerCmd())
	return c
}

type opt struct {
	logQueries bool
	ecsEnabled bool
}

type router struct {
	opt opt

	// not nil
	ctx        context.Context
	cancel     context.CancelCauseFunc
	logger     *zap.Logger
	metricsReg *prometheus.Registry

	cache      *cache // not nil, noop if no backend is configured
	upstreams  map[string]*upstreamWrapper
	domainSets map[string]*domainmatcher.MixMatcher
	rules      []*rule

	fatalErr chan fatalErr
}

type fatalErr struct {
	msg string
	err error
}

func run(ctx context.Context, cfg *Config) {
	logger := mlog.L()
	routerCtx, cancel := context.WithCancelCause(ctx)
	r := &router{
		ctx:        routerCtx,
		cancel:     cancel,
		logger:     mlog.L(),
		metricsReg: newMetricsReg(),
		upstreams:  make(map[string]*upstreamWrapper),
		domainSets: make(map[string]*domainmatcher.MixMatcher),
		fatalErr:   make(chan fatalErr, 1),
	}
	r.opt.logQueries = cfg.Log.Queries
	r.opt.ecsEnabled = cfg.ECS.Enabled

	// start metrics endpoint
	if addr := cfg.Metrics.Addr; len(addr) > 0 {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			logger.Fatal("failed to start metrics endpoint server", zap.Error(err))
		}
		logger.Info("metrics endpoint server started", zap.Stringer("addr", l.Addr()))
		go func() {
			err := http.Serve(l, promhttp.HandlerFor(r.metricsReg, promhttp.HandlerOpts{}))
			r.fatal("metrics endpoint exited", err)
		}()
	}

	// init upstreams
	for i, upstreamCfg := range cfg.Upstreams {
		err := r.initUpstream(&upstreamCfg)
		if err != nil {
			logger.Fatal("failed to init upstream", zap.Int("idx", i), zap.Error(err))
		}
	}

	// init domain sets
	for i, domainSet := range cfg.DomainSets {
		err := r.loadDomainSet(&domainSet)
		if err != nil {
			logger.Fatal("failed to init domain set", zap.Int("idx", i), zap.Error(err))
		}
	}

	// init rules
	for i, ruleCfg := range cfg.Rules {
		ru, err := r.loadRule(&ruleCfg)
		if err != nil {
			logger.Fatal("invalid rule", zap.Int("idx", i), zap.Error(err))
		}
		r.rules = append(r.rules, ru)
	}

	// init cache
	cache, err := r.initCache(&cfg.Cache)
	if err != nil {
		logger.Fatal("failed to init cache", zap.Error(err))
	}
	r.cache = cache

	// start servers
	for i, serverCfg := range cfg.Servers {
		err := r.startServer(&serverCfg)
		if err != nil {
			logger.Fatal("failed to start server", zap.Int("idx", i), zap.Error(err))
		}
	}

	runtime.GC()
	debug.FreeOSMemory()
	logger.Info("router is up and running")

	// TODO: Graceful shutdown?
	exitSigChan := make(chan os.Signal, 1)
	signal.Notify(exitSigChan, append([]os.Signal{os.Interrupt}, exitSig...)...)
	select {
	case sig := <-exitSigChan:
		logger.Info("exit signal received", zap.Stringer("sig", sig))
		os.Exit(0)
	case <-ctx.Done():
		err := context.Cause(ctx)
		logger.Info("router context closed", zap.NamedError("cause", err))
		os.Exit(0)
	case fatalErr := <-r.fatalErr:
		logger.Fatal(fatalErr.msg, zap.Error(fatalErr.err))
	}
}

func (r *router) fatal(msg string, err error) {
	select {
	case r.fatalErr <- fatalErr{msg: msg, err: err}:
	default:
	}
}

var (
	errRequestTimeout = errors.New("request timeout")
)

// rc will always have a non-nil response msg.
// Does not take the ownership of the m and rc.
func (r *router) handleServerReq(m *dnsmsg.Msg, rc *RequestContext) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second*6, errRequestTimeout)
	defer func() {
		cancel()
		if rc.Response.Msg == nil { // Make sure always returns a resp
			rc.Response.Msg = makeEmptyRespM(m, dnsmsg.RCodeServerFailure)
		}
	}()

	for _, f := range MiddlewarePreProcessors {
		f(ctx, m, rc)
		if ctxDone(ctx) {
			return
		}
		if rc.Response.Msg != nil {
			goto postMiddlewares // skip router's rules
		}
	}

	r.handleReqMsg(ctx, m, rc)
	if ctxDone(ctx) {
		return
	}

postMiddlewares:
	for i, f := range MiddlewarePostProcessors {
		f(ctx, m, rc)
		if ctxDone(ctx) {
			return
		}
		if rc.Response.Msg == nil {
			r.logger.Error("misbehaved post middleware, nil response", zap.Int("middleware_idx", i))
			break
		}
	}
}

func makeEmptyRespM(m *dnsmsg.Msg, rcode dnsmsg.RCode) *dnsmsg.Msg {
	resp := dnsmsg.NewMsg()
	resp.ID = m.ID
	resp.OpCode = m.OpCode
	resp.Response = true
	resp.RecursionDesired = m.RecursionDesired
	resp.RCode = rcode
	for n := m.Questions.Head(); n != nil; n = n.Next() {
		resp.Questions.Add(n.Value().Copy())
	}
	return resp
}

func (r *router) handleReqMsg(ctx context.Context, m *dnsmsg.Msg, rc *RequestContext) {
	hdr := m.Header
	notImpl := hdr.Response ||
		!hdr.RecursionDesired ||
		hdr.OpCode != dnsmsg.OpCode(0) ||
		m.Questions.Len() != 1

	if notImpl {
		r.logger.Check(zap.WarnLevel, "suspicious query msg").Write(
			zap.Stringer("remote", rc.RemoteAddr),
			zap.Stringer("local", rc.LocalAddr),
		)
		rc.Response.Msg = makeEmptyRespM(m, dnsmsg.RCodeNotImplemented)
	} else {
		q := m.Questions.Head().Value().Copy()
		asciiToLower(q.Name.B())
		defer dnsmsg.ReleaseQuestion(q)

		r.handleReq(ctx, q, rc)

		clientSupportEDNS0 := false
		for n := m.Additionals.Head(); n != nil; n = n.Next() {
			if n.Value().Type == dnsmsg.TypeOPT {
				clientSupportEDNS0 = true
				break
			}
		}

		if clientSupportEDNS0 {
			addOrReplaceOpt(rc.Response.Msg, udpSize)
		} else {
			// remove opt from resp
			removeOpt(rc.Response.Msg)
		}

		if r.opt.logQueries {
			r.logger.Check(zap.InfoLevel, "query summary").Write(inlineQ(q), zap.Inline(rc)) // TODO: Better struct. Do not use inline.
		}
	}

	rc.Response.Msg.Header.ID = m.Header.ID
	rc.Response.Msg.Header.Response = true
	rc.Response.Msg.Header.OpCode = m.Header.OpCode
	rc.Response.Msg.Header.RecursionAvailable = true
	rc.Response.Msg.Header.RecursionDesired = m.Header.RecursionDesired
}

// always returns a resp
func (r *router) handleReq(ctx context.Context, q *dnsmsg.Question, rc *RequestContext) {
	// Match rules
	var matchedRule *rule
	for i, rule := range r.rules {
		if rule.matcher != nil {
			matched := rule.matcher.Match(q.Name.B())
			if rule.reverse {
				matched = !matched
			}
			if !matched {
				continue
			}
		}
		rc.Response.RuleIdx = i
		matchedRule = rule
		break
	}

	if matchedRule == nil {
		makeEmptyResp(q, rc, uint16(dnsmsg.RCodeRefused))
		return
	}
	if rejectRCode := matchedRule.reject; rejectRCode > 0 {
		makeEmptyResp(q, rc, rejectRCode)
		return
	}
	if matchedRule.upstream == nil {
		makeEmptyResp(q, rc, uint16(dnsmsg.RCodeRefused))
		return
	}

	upstream := matchedRule.upstream

	// lookup cache
	resp, storedTime, expireTime, err := r.cache.Get(ctx, q, rc.RemoteAddr.Addr())
	if err != nil {
		r.logger.Error("cache error", zap.Error(err)) // TODO: Better message.
		makeEmptyResp(q, rc, uint16(dnsmsg.RCodeServerFailure))
		return
	}
	if r.cache.NeedPrefetch(storedTime, expireTime) {
		r.cache.AsyncSingleFlightPrefetch(q, rc.RemoteAddr, rc.LocalAddr, upstream)
	}
	if resp != nil { // cache hit
		rc.Response.Msg = resp
		rc.Response.Cached = true
		return
	}

	resp, err = r.forward(ctx, upstream, q, rc.RemoteAddr, rc.LocalAddr)
	if err != nil {
		r.logger.Error("failed to forward req", inlineQ(q), zap.String("upstream", upstream.tag), zap.Error(err))
		makeEmptyResp(q, rc, uint16(dnsmsg.RCodeServerFailure))
		return
	}
	rc.Response.Msg = resp

	// save upstream resp to cache
	r.cache.Store(q, rc.RemoteAddr.Addr(), resp)
}

func (r *router) forward(
	ctx context.Context,
	upstream *upstreamWrapper,
	q *dnsmsg.Question,
	remoteAddr, localAddr netip.AddrPort,
) (*dnsmsg.Msg, error) {
	reqWire, err := r.packReq(q, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to pack req, %w", err)
	}
	defer pool.ReleaseBuf(reqWire)

	resp, err := upstream.Exchange(ctx, reqWire.B(), remoteAddr, localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange, %w", err)
	}
	return resp, nil
}

func makeEmptyResp(q *dnsmsg.Question, rc *RequestContext, rcode uint16) {
	resp := dnsmsg.NewMsg()
	resp.Header.RCode = dnsmsg.RCode(rcode)
	resp.Questions.Add(q.Copy())
	rc.Response.Msg = resp
}

func (r *router) packReq(q *dnsmsg.Question, remoteAddr netip.AddrPort) (*pool.Buffer, error) {
	m := dnsmsg.NewMsg()
	m.Header.RecursionDesired = true
	m.Questions.Add(q.Copy())
	opt := edns0Opt(udpSize)
	if r.opt.ecsEnabled && remoteAddr.IsValid() {
		opt.Data = makeEdns0ClientSubnetReqOpt(remoteAddr.Addr())
	}
	defer dnsmsg.ReleaseMsg(m)

	b := pool.GetBuf(m.Len())
	_, err := m.Pack(b.B(), false, 0)
	if err != nil {
		pool.ReleaseBuf(b)
		return nil, err
	}
	return b, nil
}
