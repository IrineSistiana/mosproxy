package cache

import (
	"time"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/maypok86/otter"
	"github.com/prometheus/client_golang/prometheus"
)

type MemoryCache struct {
	backend otter.CacheWithVariableTTL[string, cacheEntry]

	getTotal prometheus.Counter
	hitTotal prometheus.Counter
	size     prometheus.Collector
}

func NewMemoryCache(size int) (*MemoryCache, error) {
	builder, err := otter.NewBuilder[string, cacheEntry](size)
	if err != nil {
		return nil, err
	}
	backend, err := builder.WithVariableTTL().
		Cost(func(key string, value cacheEntry) uint32 {
			// Approximate cost
			return uint32(unsafe.Sizeof(key)) + uint32(len(key)) + uint32(unsafe.Sizeof(value)) + uint32(len(value.v))
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

func (c *MemoryCache) Store(k []byte, v []byte, t Times, setNX bool) {
	ttl := time.Duration(t.CacheExpireAtUnix-time.Now().Unix()) * time.Second
	if ttl <= 0 {
		return
	}

	ks := string(k)
	e := cacheEntry{
		t: t,
		v: clone(v),
	}

	if setNX {
		c.backend.SetIfAbsent(ks, e, ttl)
	} else {
		c.backend.Set(ks, e, ttl)
	}
}

func (c *MemoryCache) Get(k []byte) (v []byte, t Times) {
	c.getTotal.Inc()
	e, ok := c.backend.Get(utils.Bytes2StrUnsafe(k))
	if ok { // key hit
		c.hitTotal.Inc()
		return e.v, e.t
	}
	return nil, Times{} // miss
}

// Always returns nil.
func (c *MemoryCache) Close() error {
	c.backend.Close()
	return nil
}

// cacheEntry is a static.
type cacheEntry struct {
	t Times
	v []byte
}

func clone[T any](s []T) []T {
	n := make([]T, len(s))
	copy(n, s)
	return n
}
