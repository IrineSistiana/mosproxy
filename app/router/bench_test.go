package router

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/upstream"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const (
	udpAddr      = "127.0.0.1:5000"
	tcpAddr      = "127.0.0.1:5001"
	httpAddr     = "127.0.0.1:5002"
	fasthttpAddr = "127.0.0.1:5003"
	httpsAddr    = "127.0.0.1:5004"
	quicAddr     = "127.0.0.1:5005"
	tlsAddr      = "127.0.0.1:5006"

	gnetAddr = "127.0.0.1:5010"

	tcpUnixAddr      = "@mosproxy_test_tcp"
	httpUnixAddr     = "@mosproxy_test_http"
	fasthttpUnixAddr = "@mosproxy_test_fasthttp"

	h2MaxStreams = 4096
)

func Benchmark_udp(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:       fmt.Sprintf("udp://%s", udpAddr),
		concurrent: 64, // TODO: packages will be dropped if this is too high. Is this normal?
		upstreamOpts: upstream.Opt{
			Control: controlSocket(
				SocketConfig{
					SO_RCVBUF: 1024 * 1024,
					SO_SNDBUF: 1024 * 1024,
				},
			),
		},
		timeout: time.Second,
	}
	loopBench(b, opts)
}

func Benchmark_tcp(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:       fmt.Sprintf("tcp://%s", tcpAddr),
		concurrent: 512,
	}
	loopBench(b, opts)
}

func Benchmark_tcp_unix(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("tcp://%s", tcpAddr),
		upstreamOpts: upstream.Opt{DialAddr: tcpUnixAddr},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_tcp_pipeline(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:       fmt.Sprintf("tcp+pipeline://%s", tcpAddr),
		concurrent: 512,
	}
	loopBench(b, opts)
}

func Benchmark_tcp_pipeline_unix(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("tcp+pipeline://%s", tcpAddr),
		upstreamOpts: upstream.Opt{DialAddr: tcpUnixAddr},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_tls(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("tls://%s", tlsAddr),
		upstreamOpts: upstream.Opt{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		concurrent:   512, // Note: high concurrent tls handshakes may boom the benchmark.
	}
	loopBench(b, opts)
}

func Benchmark_tls_pipeline(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("tls+pipeline://%s", tlsAddr),
		upstreamOpts: upstream.Opt{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_http(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("http://%s", httpAddr),
		upstreamOpts: upstream.Opt{},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_http_unix(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("http://%s", httpsAddr),
		upstreamOpts: upstream.Opt{DialAddr: httpUnixAddr},
		concurrent:   512,
	}
	loopBench(b, opts)
}

// Note for fasthttp benchmarks: The bottleneck is the http client. Not the fasthttp server.
func Benchmark_fasthttp(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("http://%s", fasthttpAddr),
		upstreamOpts: upstream.Opt{DialAddr: fasthttpAddr},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_fasthttp_unix(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("http://%s", fasthttpAddr),
		upstreamOpts: upstream.Opt{DialAddr: fasthttpUnixAddr},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_https(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("https://%s", httpsAddr),
		upstreamOpts: upstream.Opt{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		concurrent:   512, // TODO: Avoid concurrent tls handshakes that may boom the benchmark.
	}
	loopBench(b, opts)
}

func Benchmark_quic(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:         fmt.Sprintf("quic://%s", quicAddr),
		upstreamOpts: upstream.Opt{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		concurrent:   512,
	}
	loopBench(b, opts)
}

func Benchmark_gnet(b *testing.B) {
	initBenchServerOnce()
	opts := benchmarkOpts{
		addr:       fmt.Sprintf("tcp://%s", gnetAddr),
		concurrent: 512,
	}
	loopBench(b, opts)
}

var initBenchServerOnce = sync.OnceFunc(func() {
	tlsOpts := TlsConfig{
		DebugUseTempCert: true,
	}
	cfg := &Config{
		Servers: []ServerConfig{
			{Protocol: "udp", Listen: udpAddr, Udp: UdpConfig{Threads: runtime.GOMAXPROCS(-1)}, Socket: SocketConfig{SO_RCVBUF: 1024 * 1024, SO_SNDBUF: 1024 * 1024}},
			{Protocol: "tcp", Listen: tcpAddr, Tcp: TcpConfig{MaxConcurrentQueries: math.MaxInt32}},
			{Protocol: "tcp", Listen: tcpUnixAddr, Tcp: TcpConfig{MaxConcurrentQueries: math.MaxInt32}},

			{Protocol: "tls", Listen: tlsAddr, Tcp: TcpConfig{MaxConcurrentQueries: math.MaxInt32}, Tls: tlsOpts},

			{Protocol: "http", Listen: httpAddr},
			{Protocol: "http", Listen: httpUnixAddr},
			{Protocol: "https", Listen: httpsAddr, Tls: tlsOpts, Http: HttpConfig{DebugMaxStreams: h2MaxStreams}},

			{Protocol: "http", Listen: fasthttpAddr},
			{Protocol: "http", Listen: fasthttpUnixAddr},

			{Protocol: "quic", Listen: quicAddr, Tls: tlsOpts, Quic: QuicConfig{MaxStreams: math.MaxInt}},

			{Protocol: "gnet", Listen: gnetAddr, Tcp: TcpConfig{}},
		},
	}
	go func() {
		mlog.SetLvl(zerolog.Disabled) // disable log
		run(context.Background(), cfg)
	}()
	// TODO: Use chan to sync
	time.Sleep(time.Millisecond * 100) // wait server
})

type benchmarkOpts struct {
	addr         string
	upstreamOpts upstream.Opt
	concurrent   int
	timeout      time.Duration // default is 3s
}

func loopBench(b *testing.B, opts benchmarkOpts) {
	if opts.timeout <= 0 {
		opts.timeout = time.Second * 3
	}

	r := require.New(b)
	u, err := upstream.NewUpstream(opts.addr, opts.upstreamOpts)
	r.NoError(err)
	defer u.Close()

	m := new(dns.Msg)
	m.SetQuestion("test.test.", dns.TypeA)
	payload, err := m.Pack()
	r.NoError(err)

	// Check upstream config, and also warm up, init connections, etc..
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		m, err := u.ExchangeContext(ctx, payload)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		dnsmsg.ReleaseMsg(m)
	}

	lw := new(latencyWatcher)
	var failed atomic.Uint32

	n := b.N
	var nm sync.Mutex
	next := func() bool {
		nm.Lock()
		defer nm.Unlock()
		if n <= 0 {
			return false
		}
		n--
		return true
	}

	concurrentFn := func() {
		for next() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			start := time.Now()
			m, err := u.ExchangeContext(ctx, payload)
			latency := time.Since(start)
			cancel()
			if err != nil {
				b.Logf("t:= %s, err: %s, after %dms", time.Now(), err, time.Since(start).Milliseconds())
				failed.Add(1)
				continue
			}
			dnsmsg.ReleaseMsg(m)
			lw.observe(uint32(latency.Milliseconds()))
		}
	}

	b.ResetTimer()
	start := time.Now()

	wg := new(sync.WaitGroup)
	for i := 0; i < opts.concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrentFn()
		}()
	}
	wg.Wait()
	b.StopTimer()

	elapsed := time.Since(start).Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "op/s")
	}
	b.ReportMetric(float64(failed.Load()), "failures")
	if hide, _ := strconv.ParseBool(os.Getenv("MOSPROXY_BENCH_HIDE_LATENCY_REPORT")); !hide {
		fmt.Printf("%s\n", lw.report())
	} else {
		b.ReportMetric(float64(lw.query(0.5)), "ms(ltp50)")
		b.ReportMetric(float64(lw.query(0.9)), "ms(ltp90)")
		b.ReportMetric(float64(lw.query(0.99)), "ms(ltp99)")
	}
}

type latencyWatcher struct {
	t atomic.Uint32
	e [1001]atomic.Uint32
}

func (w *latencyWatcher) observe(ms uint32) {
	w.t.Add(1)
	if ms > 1000 {
		w.e[1000].Add(1)
		return
	}
	w.e[ms].Add(1)
}

func (w *latencyWatcher) query(hb float64) int {
	t := w.t.Load()
	sum := uint32(0)
	for i := range w.e {
		sum += w.e[i].Load()
		p := float64(sum) / float64(t)
		if p > hb {
			return i
		}
	}
	return len(w.e)
}

func (w *latencyWatcher) report() string {
	b := new(strings.Builder)
	b.WriteString("latency report:\n")

	t := w.t.Load()
	sum := uint32(0)
	prevP := float64(0)
	for i := range w.e {
		c := w.e[i].Load()
		if c == 0 {
			continue
		}
		sum += c
		p := float64(sum) / float64(t) * 100
		if deltaP := p - prevP; deltaP > 1 || (sum) == t {
			fmt.Fprintf(b, "latency: %dms, cum: %d (%.2f%%, +%.2f%%)\n",
				i,
				sum,
				p,
				deltaP,
			)
			prevP = p
		}
	}
	return b.String()
}
