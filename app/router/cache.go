package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/cache"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/klauspost/compress/s2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

const (
	defaultMinCacheTtl = time.Second * 5
	defaultMaxCacheTtl = time.Minute * 10
	prefetchTimeout    = time.Second * 6
)

func (r *Router) initCache(cfg *CacheConfig) (*cacheCtl, error) {
	c := new(cacheCtl)
	c.logger = r.subLogger("cache")
	c.minimumTtl = time.Duration(cfg.MinimumTTL) * time.Second
	if c.minimumTtl <= 0 {
		c.minimumTtl = defaultMinCacheTtl
	}
	c.maximumTtl = time.Duration(cfg.MaximumTTL) * time.Second
	if c.maximumTtl <= 0 {
		c.maximumTtl = defaultMaxCacheTtl
	}

	// init memory cache if configured
	if cfg.MemSize > 0 {
		memCache, err := cache.NewMemoryCache(cfg.MemSize)
		if err != nil {
			return nil, fmt.Errorf("failed to init memory cache backend, %w", err)
		}
		c.memory = memCache
		err = regMetrics(prometheus.WrapRegistererWithPrefix("cache_memory", r.metricsReg), memCache.Collectors()...)
		if err != nil {
			c.Close()
			return nil, err
		}
	}

	// init redis if configured
	if len(cfg.Redis) > 0 {
		redisCache, err := cache.NewRedisCache(cfg.Redis, r.subLogger("redis_cache"))
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c.redis = redisCache
		err = regMetrics(prometheus.WrapRegistererWithPrefix("cache_redis", r.metricsReg), redisCache.Collectors()...)
		if err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

type prefetchCtl struct {
	seed  maphash.Seed
	m     sync.Mutex
	queue map[uint64]struct{}
}

func newPrefetchCtl() *prefetchCtl {
	return &prefetchCtl{
		seed:  maphash.MakeSeed(),
		queue: make(map[uint64]struct{}),
	}
}

func (c *prefetchCtl) Reserve(key uint64) bool {
	c.m.Lock()
	defer c.m.Unlock()
	_, dup := c.queue[key]
	if dup {
		return false
	}
	c.queue[key] = struct{}{}
	return true
}

func (c *prefetchCtl) Done(key uint64) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.queue, key)
}

func (c *prefetchCtl) Key(key []byte) uint64 {
	h := maphash.Bytes(c.seed, key)
	return h
}

func (r *Router) needPrefetch(storedTime, expireTime time.Time) bool {
	prefetchThreshold := r.opt.Cache.PrefetchThreshold
	if prefetchThreshold <= 0 || prefetchThreshold >= 1 {
		prefetchThreshold = 0.25
	}

	lifeSpan := expireTime.Sub(storedTime)
	remainTtl := time.Until(expireTime)
	prefetchTtl := time.Duration(r.opt.Cache.PrefetchThreshold * float32(lifeSpan))
	return remainTtl < prefetchTtl
}

type cacheCtl struct {
	logger     *zerolog.Logger
	minimumTtl time.Duration      // Always valid. Has default value.
	maximumTtl time.Duration      // Always valid. Has default value.
	memory     *cache.MemoryCache // Maybe nil
	redis      *cache.RedisCache  // Maybe nil
}

// Store resp into cache.
// Remainder: resp must not contain EDNS0 record.
func (c *cacheCtl) Store(key []byte, q *QueryCtx) {
	if c.memory == nil && c.redis == nil {
		return
	}
	resp := q.Resp
	if resp == nil {
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
		c.logger.Error().Err(err).Msg("failed to pack resp")
		return
	}
	defer pool.ReleaseBuf(v)

	now := time.Now()
	storedTime := now
	expireTime := now.Add(ttl)

	e := c.logger.Debug()
	if e != nil {
		e.Dict("query", q.LogBasic()).
			Str("mark", q.ECSZone).
			Uint16("rcode", uint16(resp.RCode)).
			Int("ttl", int(ttl.Seconds())).
			Int("size", len(v)).
			Msg("store resp")
	}

	negativeResp := resp.RCode != dnsmsg.RCodeSuccess

	// store in memory
	if c.memory != nil {
		c.memory.Store(key, storedTime, expireTime, v, negativeResp)
	}

	// store in redis
	if c.redis != nil {
		c.redis.Store(key, storedTime, expireTime, v, negativeResp)
	}
}

// Get cache key for this query.
func (c *cacheCtl) Key(q *QueryCtx) pool.Buffer {
	b := pool.GetBuf(len(q.Question.Name.Data()) + 4 + len(q.ECSZone))
	off := copy(b, q.Question.Name.Data())
	binary.BigEndian.PutUint16(b[off:], uint16(q.Question.Class))
	off += 2
	binary.BigEndian.PutUint16(b[off:], uint16(q.Question.Type))
	off += 2
	copy(b[off:], []byte(q.ECSZone))
	return b
}

// If cache hit, Get will return a resp (not shared). It is the caller's
// responsibility to release the reap. TTLs of the reap are properly subtracted.
// Non-blocking func.
func (c *cacheCtl) GetMemoryCache(key []byte) (_ *dnsmsg.Msg, storedTime, expireTime time.Time) {
	if c.memory == nil {
		return
	}
	v, storedTime, expireTime := c.memory.Get(key)
	if v != nil {
		m, err := unpackCacheMsg(v)
		pool.ReleaseBuf(v)
		if err != nil {
			c.logger.Err(err).Msg("invalid cache data in memory")
			// TODO: Remove the invalid data here?
			return nil, time.Time{}, time.Time{}
		}
		dnsutils.SubtractTTL(m, uint32(time.Since(storedTime).Seconds()))
		return m, storedTime, expireTime
	}
	return nil, time.Time{}, time.Time{}
}

// If cache hit, Get will return a resp (not shared). It is the caller's
// responsibility to release the reap. TTLs of the reap are properly subtracted.
// It will also save a copy to memory cache if it is enabled.
// Blocking func.
func (c *cacheCtl) GetRedisCache(ctx context.Context, key []byte) (_ *dnsmsg.Msg, storedTime, expireTime time.Time) {
	if c.redis == nil {
		return
	}

	storedTime, expireTime, v := c.redis.Get(ctx, key)
	if v != nil { // hit
		m, err := unpackCacheMsg(v)
		if err != nil {
			c.logger.Err(err).Msg("invalid cache data in redis")
			// TODO: Remove the invalid data here?
			return nil, time.Time{}, time.Time{}
		}
		if c.memory != nil { // put v into memory cache
			c.memory.Store(key, storedTime, expireTime, v, true)
		}
		dnsutils.SubtractTTL(m, uint32(time.Since(storedTime).Seconds()))
		return m, storedTime, expireTime
	}
	return nil, time.Time{}, time.Time{}
}

// Always returns nil.
func (c *cacheCtl) Close() error {
	if c.memory != nil {
		c.memory.Close()
	}
	if c.redis != nil {
		c.redis.Close()
	}
	return nil
}

// Pack m into bytes.
func packCacheMsg(m *dnsmsg.Msg) (pool.Buffer, error) {
	l, err := m.MaxPackLen()
	if err != nil {
		return nil, err
	}

	packBuf := pool.GetBuf(l)
	defer pool.ReleaseBuf(packBuf)

	b := packBuf
	_, err = m.Pack(packBuf[:0], false, 0)
	if err != nil {
		return nil, err
	}

	compressMaxLen := s2.MaxEncodedLen(len(b))
	if compressMaxLen < 0 {
		return nil, s2.ErrTooLarge
	}
	compressBuf := pool.GetBuf(compressMaxLen)
	defer pool.ReleaseBuf(compressBuf)
	compressedMsgBytes := s2.Encode(compressBuf, b)
	return pool.CopyBuf(compressedMsgBytes), nil
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
