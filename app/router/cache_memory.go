package router

import (
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/maypok86/otter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type memoryCache struct {
	backend otter.CacheWithVariableTTL[string, *cacheEntry]
	logger  *zerolog.Logger

	getTotal prometheus.Counter
	hitTotal prometheus.Counter
	size     prometheus.Collector
}

func newMemoryCache(size int, logger *zerolog.Logger) (*memoryCache, error) {
	if logger == nil {
		logger = mlog.Nop()
	}
	builder, err := otter.NewBuilder[string, *cacheEntry](size)
	if err != nil {
		return nil, err
	}
	backend, err := builder.WithVariableTTL().
		Cost(func(key string, value *cacheEntry) uint32 {
			return uint32(len(key) + len(value.v))
		}).
		DeletionListener(func(key string, value *cacheEntry, cause otter.DeletionCause) {
			releaseEntry(value)
		}).Build()
	if err != nil {
		return nil, err
	}
	c := &memoryCache{backend: backend, logger: logger}
	c.getTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_memory_get_total",
		Help: "The total number of get ops",
	})
	c.hitTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_memory_hit_total",
		Help: "The total number of get ops that returned a value (hit the cache)",
	})
	c.size = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cache_memory_size",
		Help: "The current number of entries in the cache (Note: not the memory cost)",
	}, func() float64 { return float64(backend.Size()) })
	return c, nil
}

func (c *memoryCache) RegisterMetricsTo(r prometheus.Registerer) error {
	return regMetrics(r, c.getTotal, c.hitTotal, c.size)
}

func (c *memoryCache) Store(k []byte, storedTime, expireTime time.Time, v []byte, setNX bool) {
	ks := string(k)
	vCopy := copyBuf(v)
	e := newCacheEntry()
	e.l.Lock()
	e.storedTime = storedTime
	e.expireTime = expireTime
	e.k = ks
	e.v = vCopy
	e.l.Unlock()

	ttl := time.Until(expireTime)
	if setNX {
		c.backend.SetIfAbsent(ks, e, ttl)
	} else {
		c.backend.Set(ks, e, ttl)
	}
}

func (c *memoryCache) Get(k []byte) (resp *dnsmsg.Msg, storedTime, expireTime time.Time) {
	c.backend.Stats()
	c.getTotal.Inc()
	e, ok := c.backend.Get(bytes2StrUnsafe(k))
	if ok { // key hit
		if e.l.TryRLock() {
			if e.v == nil || e.k != string(k) { // entry has been released or reused
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{}
			}

			resp, err := unpackCacheMsg(e.v)
			storedTime = e.storedTime
			expireTime = e.expireTime
			e.l.RUnlock()

			if err != nil { // Broken data, internal error
				c.backend.Delete(bytes2StrUnsafe(k))
				c.logger.Error().Err(err).Msg("failed to unpack cached resp")
				return nil, time.Time{}, time.Time{}
			}
			c.hitTotal.Inc()
			return resp, storedTime, expireTime
		}
		return nil, time.Time{}, time.Time{} // entry is being released
	}
	return nil, time.Time{}, time.Time{} // miss
}

// Always returns nil.
func (c *memoryCache) Close() error {
	c.backend.Close()
	return nil
}

type cacheEntry struct {
	l          sync.RWMutex
	storedTime time.Time
	expireTime time.Time
	k          string
	v          pool.Buffer
}

var cacheEntryPool = sync.Pool{
	New: func() any { return new(cacheEntry) },
}

func newCacheEntry() *cacheEntry {
	return cacheEntryPool.Get().(*cacheEntry)
}

func releaseEntry(e *cacheEntry) {
	e.l.Lock()
	e.storedTime = time.Time{}
	e.expireTime = time.Time{}
	e.k = ""
	if e.v != nil {
		pool.ReleaseBuf(e.v)
		e.v = nil
	}
	e.l.Unlock()
	cacheEntryPool.Put(e)
}
