package router

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/netlist"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/dgraph-io/ristretto/z"
	"github.com/klauspost/compress/s2"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const (
	defaultMaxCacheTtl = time.Hour * 6
	prefetchTimeout    = time.Second * 6
)

func (r *router) initCache(cfg *CacheConfig) (*cache, error) {
	c := new(cache)
	c.r = r
	c.logger = r.logger.Named("cache")
	c.maximumTtl = time.Duration(cfg.MaximumTTL) * time.Second
	if c.maximumTtl <= 0 {
		c.maximumTtl = defaultMaxCacheTtl
	}

	// init memory cache if configured
	if cfg.MemSize > 0 {
		memCache, err := newMemoryCache(cfg.MemSize, c.logger.Named("memory"))
		if err != nil {
			return nil, fmt.Errorf("failed to init memory cache backend, %w", err)
		}
		c.memory = memCache
		if err := memCache.RegisterMetricsTo(r.metricsReg); err != nil {
			return nil, err
		}
	}

	// init redis if configured
	if len(cfg.Redis) > 0 {
		rc, err := newRedisCache(cfg.Redis, c.logger.Named("redis"))
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c.redis = rc
		if err := rc.RegisterMetricsTo(r.metricsReg); err != nil {
			return nil, err
		}
	}

	if len(cfg.IpMarker) > 0 {
		marker, err := loadIpMarkerFromFile(cfg.IpMarker)
		if err != nil {
			return nil, fmt.Errorf("failed to load ip marker, %w", err)
		}
		c.logger.Info(
			"ip marker file loaded",
			zap.String("file", cfg.IpMarker),
			zap.Int("length", marker.IpLen()),
			zap.Int("marks", marker.MarkLen()),
		)
		c.ipMarker = marker
	}

	c.prefetch = cfg.Prefetch
	if c.prefetch {
		c.prefetching = make(map[uint64]struct{})
	}

	c.prefetchTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_prefetch_total",
		Help: "The total number of queries that prefetched",
	})
	err := regMetrics(c.r.metricsReg, c.prefetchTotal)
	if err != nil {
		return nil, err
	}

	return c, nil
}

type cache struct {
	r          *router
	logger     *zap.Logger
	maximumTtl time.Duration // Always valid. Has default value.
	ipMarker   *ipMarker     // Maybe nil.
	memory     *memoryCache  // Maybe nil
	redis      *redisCache   // Maybe nil

	prefetch    bool
	prefetchMu  sync.Mutex
	prefetching map[uint64]struct{} // nil, if prefetch == false

	prefetchTotal prometheus.Counter
}

func (c *cache) Store(q *dnsmsg.Question, clientAddr netip.Addr, resp *dnsmsg.Msg) {
	if c.memory == nil && c.redis == nil {
		return
	}
	if resp == nil || resp.Header.Truncated {
		return
	}

	u, hasRr := dnsutils.GetMinimalTTL(resp)
	msgRrMinTtl := time.Duration(u) * time.Second

	var ttl time.Duration
	switch resp.Header.RCode {
	case dnsmsg.RCodeNameError: // NXDOMAIN, cache for 30s
		const defaultTtl = time.Second * 30
		if hasRr {
			ttl = min(defaultTtl, msgRrMinTtl)
		} else {
			ttl = defaultTtl
		}
	case dnsmsg.RCodeServerFailure: // SERVFAIL, cache for 1s
		const defaultTtl = time.Second * 1
		if hasRr {
			ttl = min(defaultTtl, msgRrMinTtl)
		} else {
			ttl = defaultTtl
		}
	case dnsmsg.RCodeSuccess:
		const defaultTtl = time.Second * 30
		if hasRr {
			ttl = msgRrMinTtl
		} else {
			// SUCCESS, but no record, cache for 30s
			// TODO: Use minttl from SOA record.
			ttl = defaultTtl
		}
	default: // Other rcode. cache for 5s
		const defaultTtl = time.Second * 5
		if hasRr {
			ttl = min(defaultTtl, msgRrMinTtl)
		} else {
			ttl = defaultTtl
		}
	}

	// Minimum ttl is 1.
	if ttl <= 0 {
		ttl = time.Second
	}
	// Apply maximum.
	if ttl > c.maximumTtl {
		ttl = c.maximumTtl
	}

	v, err := packCacheMsg(resp)
	if err != nil {
		c.logger.Error(logPackRespErr, zap.Error(err))
		return
	}
	defer pool.ReleaseBuf(v)

	mark := c.ipMark(clientAddr)

	now := time.Now()
	storedTime := now
	expireTime := now.Add(ttl)

	// store in memory
	if c.memory != nil {
		c.memory.Store(q, mark, storedTime, expireTime, v.B())
	}

	// store in redis
	if c.redis != nil {
		c.redis.AsyncStore(q, mark, storedTime, expireTime, v.B())
	}
}

func (c *cache) AsyncSingleFlightPrefetch(q *dnsmsg.Question, remoteAddr, localAddr netip.AddrPort, u *upstreamWrapper) {
	mark := c.ipMark(remoteAddr.Addr())
	prefetchKey := hashReq(q, mark)
	c.prefetchMu.Lock()
	_, dup := c.prefetching[prefetchKey]
	if !dup {
		c.prefetching[prefetchKey] = struct{}{}
	}
	c.prefetchMu.Unlock()
	if !dup {
		q := q.Copy() // q is not concurrent save. Copy it.
		pool.Go(func() {
			defer dnsmsg.ReleaseQuestion(q)
			c.doPreFetch(prefetchKey, q, remoteAddr, localAddr, u)
		})
	}
}

func (c *cache) NeedPrefetch(storedTime, expireTime time.Time) bool {
	if !c.prefetch {
		return false
	}
	lifeSpan := expireTime.Sub(storedTime)
	ttl := time.Until(expireTime)
	// do prefetch if the ttl is small than its 12.5% life span
	return ttl < (lifeSpan >> 3)
}

func (c *cache) doPreFetch(prefetchKey uint64, q *dnsmsg.Question, remoteAddr, localAddr netip.AddrPort, u *upstreamWrapper) {
	defer func() {
		c.prefetchMu.Lock()
		delete(c.prefetching, prefetchKey)
		c.prefetchMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(c.r.ctx, prefetchTimeout)
	defer cancel()
	resp, err := c.r.forward(ctx, u, q, remoteAddr, localAddr)
	if err != nil {
		c.logger.Check(zap.WarnLevel, "failed to prefetch").Write(
			inlineQ(q),
			zap.String("upstream", u.tag),
			zap.Error(err),
		)
		return
	}
	c.prefetchTotal.Inc()
	c.Store(q, remoteAddr.Addr(), resp)
}

// If cache hit, Get will return a resp (not shared). It is the caller's
// responsibility to release the reap. TTLs of the reap are properly subtracted.
// ip can be invalid, then mark 0 will be used.
// The ctx is for redis cache, and the error, if not nil, will be a redis io error.
// Invalid msg/data error will be logged instead of returning an error.
func (c *cache) Get(ctx context.Context, q *dnsmsg.Question, clientAddr netip.Addr) (resp *dnsmsg.Msg, storedTime, expireTime time.Time, err error) {
	if c.memory == nil && c.redis == nil {
		return
	}

	ipMark := c.ipMark(clientAddr)

	// memory cache
	if c.memory != nil {
		resp, storedTime, expireTime = c.memory.Get(q, ipMark)
		if resp != nil {
			dnsutils.SubtractTTL(resp, uint32(time.Since(storedTime).Seconds()))
			return
		}
	}

	// memory cache missed, try redis
	if c.redis != nil {
		var v []byte
		storedTime, expireTime, resp, v, err = c.redis.Get(ctx, q, ipMark)
		if err != nil { // redis io error
			return
		}
		if resp != nil { // hit
			if c.memory != nil { // put v into memory cache
				c.memory.Store(q, ipMark, storedTime, expireTime, v)
			}
			dnsutils.SubtractTTL(resp, uint32(time.Since(storedTime).Seconds()))
			return
		}
	}
	return
}

// Lookup the mark of the addr.
// For convenience, if c.ipMarker==nil || addr is not valid, returns "".
func (c *cache) ipMark(addr netip.Addr) string {
	if c.ipMarker == nil || !addr.IsValid() {
		return ""
	}
	return c.ipMarker.Mark(addr)
}

// Always returns nil.
func (c *cache) Close() error {
	if c.memory != nil {
		c.memory.Close()
	}
	if c.redis != nil {
		c.redis.Close()
	}
	return nil
}

// Hash the request key.
func hashReq(q *dnsmsg.Question, ipMark string) (hash uint64) {
	h1 := z.MemHash(q.Name.B())
	h1 += uint64(q.Class) << 16
	h1 += uint64(q.Type)
	h2 := z.MemHashString(ipMark)
	return h1 ^ h2
}

// Pack m into bytes. EDNS0 Opt will be ignored.
func packCacheMsg(m *dnsmsg.Msg) (*pool.Buffer, error) {
	noOpt := func(sec dnsmsg.MsgSection, rr *dnsmsg.Resource) bool {
		return sec == dnsmsg.SectionAdditional && rr.Type == dnsmsg.TypeOPT
	}

	packBuf := pool.GetBuf(m.Len())
	defer pool.ReleaseBuf(packBuf)
	n, err := m.PackFilter(packBuf.B(), false, 0, noOpt)
	if err != nil {
		return nil, err
	}
	msgBytes := packBuf.B()[:n]

	compressMaxLen := s2.MaxEncodedLen(len(msgBytes))
	if compressMaxLen < 0 {
		return nil, s2.ErrTooLarge
	}
	compressBuf := pool.GetBuf(compressMaxLen)
	defer pool.ReleaseBuf(compressBuf)
	compressedMsgBytes := s2.Encode(compressBuf.B(), msgBytes)
	return copyBuf(compressedMsgBytes), nil
}

func unpackCacheMsg(m []byte) (*dnsmsg.Msg, error) {
	l, err := s2.DecodedLen(m)
	if err != nil {
		return nil, fmt.Errorf("s2 decode len: %w", err)
	}
	decodeBuf := pool.GetBuf(l)
	defer pool.ReleaseBuf(decodeBuf)
	decoded, err := s2.Decode(decodeBuf.B(), m)
	if err != nil {
		return nil, fmt.Errorf("s2 decode: %w", err)
	}
	return dnsmsg.UnpackMsg(decoded)
}

type ipMarker struct {
	l *netlist.List[int]
	s []string
}

func (m *ipMarker) Mark(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	idx, ok := m.l.LookupAddr(addr)
	if !ok {
		return ""
	}
	return m.s[idx]
}

func (m *ipMarker) IpLen() int {
	return m.l.Len()
}

func (m *ipMarker) MarkLen() int {
	return len(m.s)
}

func loadIpMarkerFromReader(r io.Reader) (*ipMarker, error) {
	parseLine := func(s string) (_ netip.Addr, _ netip.Addr, _ string, err error) {
		t, s, ok := strings.Cut(s, ",")
		if !ok {
			err = errors.New("missing first comma")
			return
		}
		start, err := netip.ParseAddr(t)
		if err != nil {
			err = fmt.Errorf("invalid start addr, %w", err)
			return
		}
		t, s, ok = strings.Cut(s, ",")
		if !ok {
			err = errors.New("missing second comma")
			return
		}
		end, err := netip.ParseAddr(t)
		if err != nil {
			err = fmt.Errorf("invalid end addr, %w", err)
			return
		}
		return start, end, s, nil
	}

	listBuilder := netlist.NewBuilder[int](0)
	labelIndexes := make(map[string]int)
	labels := make([]string, 0)
	assignIdx := func(s string) (idx int) {
		idx, ok := labelIndexes[s]
		if ok {
			return idx
		}
		labels = append(labels, s)
		idx = len(labels) - 1
		labelIndexes[s] = idx
		return idx
	}

	scanner := bufio.NewScanner(r)
	line := 0
	for scanner.Scan() {
		line++
		t := scanner.Text()
		t, _, _ = strings.Cut(t, "#")
		t = strings.TrimSpace(t)
		if len(t) == 0 {
			continue
		}
		start, end, markStr, err := parseLine(t)
		if err != nil {
			return nil, fmt.Errorf("invalid line #%d, %w", line, err)
		}
		idx := assignIdx(markStr)
		if ok := listBuilder.Add(start, end, idx); !ok {
			return nil, fmt.Errorf("invalid range at line #%d", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	l, err := listBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build ip list, %w", err)
	}
	return &ipMarker{
		l: l,
		s: labels,
	}, nil
}

func loadIpMarkerFromFile(fp string) (*ipMarker, error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return loadIpMarkerFromReader(f)
}
