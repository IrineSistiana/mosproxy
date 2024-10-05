package proxy

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/IrineSistiana/mosproxy/app"
	"github.com/IrineSistiana/mosproxy/app/router"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func init() {
	app.RootCmd().AddCommand(newProxyCmd())
}

func newProxyCmd() *cobra.Command {
	var (
		listen             string
		protocol           string
		tlsCert            string
		tlsKey             string
		httpPath           string
		upstreams          []string
		upstreamLb         string
		ecs                bool
		ecsIpZone          string
		cache              int
		cacheRedis         string
		cacheOptimisticTTL int
		accessLog          bool
	)
	c := &cobra.Command{
		Use:   "proxy -u upstream_addr [-u upstream_addr] [flags]",
		Short: "Start a dns proxy service via command line",
		Long: "Start a dns proxy service via command line. e.g:" +
			"\nProxy from 0.0.0.0:5353 to Google DoH." +
			"\n\t`proxy -l 0.0.0.0:5353 -u https://dns.google/dns-query`" +
			"\nProxy to Cloudflare DNS, send client subnet to upstream, and use Google DNS as fallback." +
			"\n\t`proxy -l 0.0.0.0:5353 -u 1.1.1.1 -u 8.8.8.8 --upstream-lb fall_through --ecs`",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			logger := mlog.L()
			cfg := router.Config{}
			if len(protocol) == 0 {
				cfg.Servers = []router.ServerConfig{
					{Listen: listen, Protocol: "udp"},
					{Listen: listen, Protocol: "tcp"},
				}
			} else {
				cfg.Servers = []router.ServerConfig{
					{
						Listen:   listen,
						Protocol: protocol,
						Tls: router.TlsConfig{
							Certs: []string{tlsCert},
							Keys:  []string{tlsKey},
						},
					},
				}
			}

			if len(upstreams) == 0 {
				logger.Fatal().Msg("no upstream is configured")
			}
			for _, u := range upstreams {
				var (
					tag      string
					dialAddr string
					maxFails int
					insecure bool
				)
				if !strings.Contains(u, "://") {
					u = "udp://" + u
				}
				addr, err := url.Parse(u)
				if err != nil {
					logger.Fatal().Err(err).Msg("invalid upstream url")
				}
				q := addr.Query()
				tag = q.Get("tag")
				if len(tag) == 0 {
					tag = u
				}
				dialAddr = q.Get("dial_addr")

				s := q.Get("max_fails")
				if len(s) > 0 {
					var err error
					maxFails, err = strconv.Atoi(s)
					if err != nil {
						logger.Fatal().Err(err).Msg("invalid max_fails arg in upstream url")
					}
				} else {
					maxFails = 5
				}

				s = q.Get("insecure")
				if len(s) > 0 {
					var err error
					insecure, err = strconv.ParseBool(s)
					if err != nil {
						logger.Fatal().Err(err).Msg("invalid insecure arg in upstream url")
					}
				}

				addr.RawQuery = "" // drop all queries before init upstream
				cfg.Upstreams = append(cfg.Upstreams, router.UpstreamConfig{
					Tag:      tag,
					Addr:     addr.String(),
					DialAddr: dialAddr,
					Tls:      router.TlsConfig{InsecureSkipVerify: insecure},
					HealthCheck: router.HealthCheckConfig{
						MaxFails: maxFails,
					},
				})
			}
			lbCfg := router.LoadBalancerConfig{
				Tag:    "lb",
				Method: upstreamLb,
			}
			for _, u := range cfg.Upstreams {
				lbCfg.Backends = append(lbCfg.Backends, router.LoadBalancerBackendConfig{Tag: u.Tag})
			}
			cfg.LoadBalancers = []router.LoadBalancerConfig{lbCfg}
			cfg.Rules = []router.RuleConfig{{Forward: "lb"}}

			cfg.ECS = router.ECSConfig{Enabled: ecs, Forward: ecs, IpZone: ecsIpZone}
			cfg.Cache = router.CacheConfig{
				MemSize:       cache,
				Redis:         cacheRedis,
				OptimisticTTL: cacheOptimisticTTL,
				MaximumTTL:    3600 * 24,
			}
			cfg.Log = router.LogConfig{Queries: accessLog}

			r, err := router.Run(&cfg)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to start router")
			}

			exitSigChan := make(chan os.Signal, 1)
			signal.Notify(exitSigChan, os.Interrupt)

			var shutdownLog *zerolog.Event
			select {
			case sig := <-exitSigChan:
				err = fmt.Errorf("signal %s", sig)
				shutdownLog = logger.Info()
				goto shutdown
			case <-r.Context().Done():
				err = context.Cause(r.Context())
				shutdownLog = logger.Error()
				goto shutdown
			}

		shutdown:
			shutdownLog.AnErr("cause", err).Msg("proxy exiting")
			r.Close(err)
			logger.Info().Msg("proxy exited")
			os.Exit(0)
		},
	}
	fs := c.Flags()
	fs.StringVarP(&listen, "listen", "l", "127.0.0.1:53", "Listening address.")
	fs.StringVarP(&protocol, "protocol", "p", "", "Listening protocol.\nOne of [udp|tcp|tls|http|fasthttp|https|quic].\nDefault is listening both udp and tcp.")
	fs.StringVar(&tlsCert, "tls-cert", "", "Path to a file of PEM certificate.")
	fs.StringVar(&tlsKey, "tls-key", "", "Path to a file of PEM private key.")
	fs.StringVar(&httpPath, "http-path", "", "Http path of DoH server.")
	usage := "Upstream addr (can be specified multiple times)." +
		"\nFormat: [protocol://]host[:port][/path][?arg_key=arg_value][&arg_key=arg_value]..." +
		"\nprotocol can be one of: [udp|tcp[+pipeline]|tls[+pipeline]|https|h3|quic]" +
		"\nSupported arg_key:" +
		"\n\ttag: Tag name for this upstream, useful for logging." +
		"\n\tdial_addr: IP addr of the host." +
		"\n\tmax_fails: If the upstream failed max_fails times continuously, mark it as offline. (default 5)" +
		"\n\tinsecure: [true] Disable TLS server verification." +
		"\ne.g.: tcp://8.8.8.8:53, https://dns.google/dns-query?dial_addr=8.8.8.8&tag=google_doh"
	fs.StringSliceVarP(&upstreams, "upstream", "u", nil, usage)
	usage = "Upstream load balance mode:" +
		"\n\trandom: Use random online upstream." +
		"\n\tfall_through: Fallback to next online upstream if previous one was offline." +
		"\n\tqname_hash: Queries with same domain name will use the same online upstream." +
		"\n\tclient_ip_hash: Queries from same ip will use the same online upstream."
	fs.StringVar(&upstreamLb, "upstream-lb", "random", usage)
	fs.BoolVar(&ecs, "ecs", false, "Send EDNS0 Client Subnet (ECS) to upstream.")
	fs.StringVar(&ecsIpZone, "ecs-ip-zone", "", "Path to ecs ip zone file.")
	fs.IntVar(&cache, "cache", 4*1024*1024, "Memory cache size in bytes (0: disable memory cache).")
	usage = "Redis cache backend address.\nIf memory and redis cache are both enabled, redis will work as a second level cache." +
		"\nFormat:" +
		"\n\tredis://<user>:<password>@<host>:<port>/<db_number>?addr=<host2>:<port2>&addr=<host3>:<port3>" +
		"\n\tunix://<user>:<password>@</path/to/redis.sock>?db=<db_number>"
	fs.StringVar(&cacheRedis, "cache-redis", "", usage)
	fs.IntVar(&cacheOptimisticTTL, "cache-optimistic-ttl", 0, "If > 0, enable optimistic cache.")
	fs.BoolVar(&accessLog, "access-log", false, "Print all queries to log.")
	return c
}
