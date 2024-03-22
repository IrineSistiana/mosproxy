package router

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
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
	"github.com/klauspost/compress/s2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

const (
	defaultMaxCacheTtl = time.Hour * 6
	prefetchTimeout    = time.Second * 6
)

func (r *router) initCache(cfg *CacheConfig) (*cache, error) {
	c := new(cache)
	c.r = r
	c.logger = r.subLogger("cache")
	c.maximumTtl = time.Duration(cfg.MaximumTTL) * time.Second
	if c.maximumTtl <= 0 {
		c.maximumTtl = defaultMaxCacheTtl
	}

	// init memory cache if configured
	if cfg.MemSize > 0 {
		memCache, err := newMemoryCache(cfg.MemSize, r.subLogger("mem_cache"))
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
		rc, err := newRedisCache(cfg.Redis, r.subLogger("redis_cache"))
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
		c.logger.Info().
			Str("file", cfg.IpMarker).
			Int("len", marker.IpLen()).
			Int("marks", marker.MarkLen()).
			Msg("ip marker file loaded")
		c.ipMarker = marker
	}

	c.prefetching = make(map[uint64]struct{})
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
	r          *router // TODO: Avoid cross ref.
	logger     *zerolog.Logger
	maximumTtl time.Duration // Always valid. Has default value.
	ipMarker   *ipMarker     // Maybe nil.
	memory     *memoryCache  // Maybe nil
	redis      *redisCache   // Maybe nil

	prefetchMu    sync.Mutex
	prefetching   map[uint64]struct{}
	prefetchTotal prometheus.Counter
}

// Store resp into cache.
// Remainder: resp must not contain EDNS0 record.
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
		c.logger.Error().Err(err).Msg(logPackRespErr)
		return
	}
	defer pool.ReleaseBuf(v)

	mark := c.ipMark(clientAddr)

	now := time.Now()
	storedTime := now
	expireTime := now.Add(ttl)

	c.logger.Debug().
		Object("query", (*qLogObj)(q)).
		Str("mark", mark).
		Uint16("rcode", uint16(resp.RCode)).
		Int("ttl", int(ttl.Seconds())).
		Int("size", len(v)).
		Msg("store resp")

	k := cacheKey(q, mark)
	defer pool.ReleaseBuf(k)
	negativeResp := resp.RCode != dnsmsg.RCodeSuccess

	// store in memory
	if c.memory != nil {
		c.memory.Store(k, storedTime, expireTime, v, negativeResp)
	}

	// store in redis
	if c.redis != nil {
		c.redis.AsyncStore(k, storedTime, expireTime, v, negativeResp)
	}
}

func (c *cache) AsyncSingleFlightPrefetch(q *dnsmsg.Question, remoteAddr netip.AddrPort, u *upstreamWrapper) {
	mark := c.ipMark(remoteAddr.Addr())
	prefetchKey := prefetchKey(q, mark)
	c.prefetchMu.Lock()
	_, dup := c.prefetching[prefetchKey]
	if !dup {
		c.prefetching[prefetchKey] = struct{}{}
	}
	c.prefetchMu.Unlock()
	if !dup {
		q := q.Copy() // q is not concurrent save. Copy it.
		go func() {
			c.doPreFetch(q, remoteAddr, u)

			dnsmsg.ReleaseQuestion(q)
			c.prefetchMu.Lock()
			delete(c.prefetching, prefetchKey)
			c.prefetchMu.Unlock()
		}()
	}
}

func (c *cache) NeedPrefetch(storedTime, expireTime time.Time) bool {
	lifeSpan := expireTime.Sub(storedTime)
	ttl := time.Until(expireTime)
	// do prefetch if the ttl is small than its 25% life span
	return ttl < (lifeSpan >> 2)
}

func (c *cache) doPreFetch(q *dnsmsg.Question, remoteAddr netip.AddrPort, u *upstreamWrapper) {
	c.logger.Debug().Object("query", (*qLogObj)(q)).Str("upstream", u.tag).Msg("prefetching cache")

	ctx, cancel := context.WithTimeout(c.r.ctx, prefetchTimeout)
	defer cancel()
	resp, err := c.r.forward(ctx, u, q, remoteAddr)
	if err != nil {
		c.logger.Warn().Object("query", (*qLogObj)(q)).Str("upstream", u.tag).Err(err).
			Msg("failed to prefetch")
		return
	}
	c.prefetchTotal.Inc()
	c.Store(q, remoteAddr.Addr(), resp)
}

// If cache hit, Get will return a resp (not shared). It is the caller's
// responsibility to release the reap. TTLs of the reap are properly subtracted.
func (c *cache) Get(ctx context.Context, q *dnsmsg.Question, rc *RequestContext) (resp *dnsmsg.Msg, storedTime, expireTime time.Time) {
	ipMark := c.ipMark(rc.RemoteAddr.Addr())
	rc.Response.IpMark = ipMark

	if c.memory == nil && c.redis == nil {
		return
	}

	key := cacheKey(q, ipMark)
	defer pool.ReleaseBuf(key)

	// memory cache
	if c.memory != nil {
		resp, storedTime, expireTime = c.memory.Get(key)
		if resp != nil {
			dnsutils.SubtractTTL(resp, uint32(time.Since(storedTime).Seconds()))
			return
		}
	}

	// memory cache missed, try redis
	if c.redis != nil {
		var v []byte
		storedTime, expireTime, resp, v = c.redis.Get(ctx, key)
		if resp != nil { // hit
			if c.memory != nil { // put v into memory cache
				c.memory.Store(key, storedTime, expireTime, v, true)
			}
			dnsutils.SubtractTTL(resp, uint32(time.Since(storedTime).Seconds()))
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

var mhSeed = maphash.MakeSeed()

// Hash the request for prefetch
func prefetchKey(q *dnsmsg.Question, ipMark string) uint64 {
	h1 := maphash.Bytes(mhSeed, q.Name)
	h1 += uint64(q.Class) << 16
	h1 += uint64(q.Type)
	h2 := maphash.String(mhSeed, ipMark)
	return h1 ^ h2
}

// Pack m into bytes.
func packCacheMsg(m *dnsmsg.Msg) (pool.Buffer, error) {
	packBuf := pool.GetBuf(m.Len())
	defer pool.ReleaseBuf(packBuf)
	b := packBuf
	n, err := m.Pack(b, false, 0)
	if err != nil {
		return nil, err
	}
	b = b[:n]

	compressMaxLen := s2.MaxEncodedLen(len(b))
	if compressMaxLen < 0 {
		return nil, s2.ErrTooLarge
	}
	compressBuf := pool.GetBuf(compressMaxLen)
	defer pool.ReleaseBuf(compressBuf)
	compressedMsgBytes := s2.Encode(compressBuf, b)
	return copyBuf(compressedMsgBytes), nil
}

func unpackCacheMsg(m []byte) (*dnsmsg.Msg, error) {
	l, err := s2.DecodedLen(m)
	if err != nil {
		return nil, fmt.Errorf("s2 decode len: %w", err)
	}
	decodeBuf := pool.GetBuf(l)
	defer pool.ReleaseBuf(decodeBuf)
	decoded, err := s2.Decode(decodeBuf, m)
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

func cacheKey(q *dnsmsg.Question, mark string) pool.Buffer {
	b := pool.GetBuf(len(q.Name) + 4 + len(mark))
	off := copy(b, q.Name)
	binary.BigEndian.AppendUint16(b[off:], uint16(q.Class))
	off += 2
	binary.BigEndian.PutUint16(b[off:], uint16(q.Type))
	off += 2
	copy(b[off:], []byte(mark))
	return b
}
