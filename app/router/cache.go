package router

import (
	"context"
	"fmt"
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
	defaultMaxCacheTtl = 24 * 3600 // 1d
	prefetchTimeout    = time.Second * 6
)

func (r *Router) initCache(cfg *CacheConfig) (*CacheCtl, error) {
	c := new(CacheCtl)
	c.logger = r.subLogger("cache")
	c.maximumTtl = cfg.MaximumTTL
	if c.maximumTtl <= 0 {
		c.maximumTtl = defaultMaxCacheTtl
	}
	c.optimisticTtl = cfg.OptimisticTTL

	// init memory cache if configured
	if cfg.MemSize > 0 {
		memCache, err := cache.NewMemoryCache(cfg.MemSize)
		if err != nil {
			return nil, fmt.Errorf("failed to init memory cache backend, %w", err)
		}
		c.memory = memCache
		err = RegMetrics(prometheus.WrapRegistererWithPrefix("cache_memory", r.metricsReg), memCache.Collectors()...)
		if err != nil {
			c.close()
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
		err = RegMetrics(prometheus.WrapRegistererWithPrefix("cache_redis", r.metricsReg), redisCache.Collectors()...)
		if err != nil {
			c.close()
			return nil, err
		}
	}
	return c, nil
}

func (r *Router) needPrefetch(t cache.Times) bool {
	prefetchThresholdRatio := r.opt.Cache.PrefetchThreshold
	if prefetchThresholdRatio <= 0 || prefetchThresholdRatio >= 1 {
		prefetchThresholdRatio = 0.25
	}

	initTtl := t.ExpireAtUnix - t.StoredAtUnix
	remainTtl := t.ExpireAtUnix - time.Now().Unix() // Note: maybe negative
	prefetchThresholdTtl := int64(r.opt.Cache.PrefetchThreshold * float32(initTtl))
	return remainTtl < prefetchThresholdTtl
}

type CacheCtl struct {
	logger        *zerolog.Logger
	maximumTtl    int // Always valid. Has default value.
	optimisticTtl int

	memory *cache.MemoryCache // Maybe nil
	redis  *cache.RedisCache  // Maybe nil
}

// No backend.
func (c *CacheCtl) Nop() bool {
	return c.memory == nil && c.redis == nil
}

// Store resp into cache.
// Note: resp must not contain EDNS0 record.
func (c *CacheCtl) Store(key []byte, resp *dnsmsg.Msg) {
	if c.memory == nil && c.redis == nil {
		return
	}
	if len(key) == 0 || resp == nil {
		return
	}

	// Check EDNS0, EDNS0 CANNOT be cached
	if hasEDNS0(resp) {
		c.logger.Error().Bytes("key", key).Msg("storing a msg with EDNS0 rr")
		return
	}

	u, hasRr := dnsutils.GetMinimalTTL(resp)
	msgRrMinTtl := int(u)
	var msgTtl int
	var applyOptimistic bool
	switch resp.Header.RCode {
	case dnsmsg.RCodeNameError: // NXDOMAIN, cache for 300s
		const defaultTtl = 300
		if hasRr {
			msgTtl = min(defaultTtl, msgRrMinTtl)
		} else {
			msgTtl = defaultTtl
		}
	case dnsmsg.RCodeServerFailure: // SERVFAIL, cache for 3s
		const defaultTtl = 3
		if hasRr {
			msgTtl = min(defaultTtl, msgRrMinTtl)
		} else {
			msgTtl = defaultTtl
		}
	case dnsmsg.RCodeSuccess:
		const defaultTtl = 300
		if hasRr {
			msgTtl = msgRrMinTtl
			applyOptimistic = true
		} else {
			// SUCCESS, but no record, cache for 300s
			// TODO: Use minttl from SOA record.
			msgTtl = defaultTtl
		}
	default: // Other rcode. cache for 5s
		const defaultTtl = 5
		if hasRr {
			msgTtl = min(defaultTtl, msgRrMinTtl)
		} else {
			msgTtl = defaultTtl
		}
	}

	if msgTtl < 1 {
		msgTtl = 1
	}
	// Apply maximum.
	if msgTtl > c.maximumTtl {
		msgTtl = c.maximumTtl
	}

	v, err := packCacheMsg(resp)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to pack resp")
		return
	}
	defer pool.ReleaseBuf(v)

	now := time.Now()

	storedTime := now.Unix()
	expireTime := storedTime + int64(msgTtl)
	cacheExpireTime := expireTime
	if c.optimisticTtl > 0 && applyOptimistic {
		cacheExpireTime += int64(c.optimisticTtl)
	}
	t := cache.Times{
		StoredAtUnix:      storedTime,
		ExpireAtUnix:      expireTime,
		CacheExpireAtUnix: cacheExpireTime,
	}

	e := c.logger.Debug()
	if e != nil {
		e.Bytes("key", key)
		e.Int("ttl", msgTtl)
		e.Int("cache_ttl", msgTtl+c.optimisticTtl)
		e.Int("size", len(v))
		e.Msg("store resp")
	}

	negativeResp := resp.RCode != dnsmsg.RCodeSuccess

	// store in memory
	if c.memory != nil {
		c.memory.Store(key, v, t, negativeResp)
	}

	// store in redis
	if c.redis != nil {
		c.redis.Store(key, v, t, negativeResp)
	}
}

// If cache hit, Get will return a resp (not shared). It is the caller's
// responsibility to release the reap. TTLs of the reap are properly subtracted.
func (c *CacheCtl) Get(ctx context.Context, key []byte) (*dnsmsg.Msg, cache.Times) {
	m, t := c.getMemoryCache(key)
	if m != nil {
		return m, t
	}
	return c.getRedisCache(ctx, key)
}

func (c *CacheCtl) getMemoryCache(key []byte) (*dnsmsg.Msg, cache.Times) {
	if c.memory == nil {
		return nil, cache.Times{}
	}
	v, t := c.memory.Get(key)
	if v != nil {
		m, err := unpackCacheMsg(v)
		if err != nil {
			c.logger.Err(err).Msg("invalid cache data in memory")
			// TODO: Remove the invalid data here?
			return nil, cache.Times{}
		}
		dnsutils.SubtractTTL(m, uint32(time.Now().Unix()-t.StoredAtUnix))
		return m, t
	}
	return nil, cache.Times{}
}

// Will also update memory cache.
func (c *CacheCtl) getRedisCache(ctx context.Context, key []byte) (*dnsmsg.Msg, cache.Times) {
	if c.redis == nil {
		return nil, cache.Times{}
	}

	v, t := c.redis.Get(ctx, key)
	if len(v) > 0 { // hit
		m, err := unpackCacheMsg(v)
		if err != nil {
			c.logger.Err(err).Msg("invalid cache data in redis")
			// TODO: Remove the invalid data here?
			return nil, cache.Times{}
		}
		if c.memory != nil { // put v into memory cache
			c.memory.Store(key, v, t, true)
		}
		dnsutils.SubtractTTL(m, uint32(time.Now().Unix()-t.StoredAtUnix))
		return m, t
	}
	return nil, cache.Times{}
}

func (c *CacheCtl) close() {
	if c.memory != nil {
		c.memory.Close()
	}
	if c.redis != nil {
		c.redis.Close()
	}
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

type prefetchCtl struct {
	m     sync.Mutex
	queue map[string]struct{}
}

func newPrefetchCtl() *prefetchCtl {
	return &prefetchCtl{
		queue: make(map[string]struct{}),
	}
}

func (c *prefetchCtl) Reserve(key []byte) (sk string, ok bool) {
	c.m.Lock()
	defer c.m.Unlock()
	_, dup := c.queue[string(key)]
	if dup {
		return "", false
	}
	s := string(key)
	c.queue[s] = struct{}{}
	return s, true
}

func (c *prefetchCtl) Done(key string) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.queue, key)
}
