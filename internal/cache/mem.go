package cache

import (
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/maypok86/otter"
	"github.com/prometheus/client_golang/prometheus"
)

type MemoryCache struct {
	backend otter.CacheWithVariableTTL[string, *cacheEntry]

	getTotal prometheus.Counter
	hitTotal prometheus.Counter
	size     prometheus.Collector
}

func NewMemoryCache(size int) (*MemoryCache, error) {
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
	c := &MemoryCache{backend: backend}
	c.getTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "get_total",
		Help: "The total number of get ops",
	})
	c.hitTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hit_total",
		Help: "The total number of get ops that returned a value (hit the cache)",
	})
	c.size = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "size",
		Help: "The current number of entries in the cache (Note: not the memory cost)",
	}, func() float64 { return float64(backend.Size()) })
	return c, nil
}

func (c *MemoryCache) Collectors() []prometheus.Collector {
	return []prometheus.Collector{c.getTotal, c.hitTotal, c.size}
}

func (c *MemoryCache) Store(k []byte, storedTime, expireTime time.Time, v []byte, setNX bool) {
	ks := string(k)
	vCopy := pool.CopyBuf(v)
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

func (c *MemoryCache) Get(k []byte) (v pool.Buffer, storedTime, expireTime time.Time) {
	c.getTotal.Inc()
	e, ok := c.backend.Get(utils.Bytes2StrUnsafe(k))
	if ok { // key hit
		if e.l.TryRLock() {
			if e.v == nil || e.k != string(k) { // entry has been released or reused
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{}
			}

			v = pool.CopyBuf(e.v)
			storedTime = e.storedTime
			expireTime = e.expireTime
			e.l.RUnlock()
			c.hitTotal.Inc()
			return v, storedTime, expireTime
		}
		return nil, time.Time{}, time.Time{} // entry is being released
	}
	return nil, time.Time{}, time.Time{} // miss
}

// Always returns nil.
func (c *MemoryCache) Close() error {
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
