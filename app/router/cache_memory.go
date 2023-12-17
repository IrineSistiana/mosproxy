package router

import (
	"bytes"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/dgraph-io/ristretto"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type memoryCache struct {
	backend *ristretto.Cache[uint64, *cacheEntry]
	logger  *zap.Logger

	getTotal prometheus.Counter
	hitTotal prometheus.Counter
}

func newMemoryCache(size int64, logger *zap.Logger) (*memoryCache, error) {
	backend, err := ristretto.NewCache[uint64, *cacheEntry](&ristretto.Config[uint64, *cacheEntry]{
		NumCounters: size / 20,
		MaxCost:     size,
		BufferItems: 64,
		Metrics:     false,
		KeyToHash:   func(key uint64) (uint64, uint64) { return key, 0 }, // Default func will alloc the uint64 to heap.
		OnExit:      releaseEntry,
	})
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
	return c, nil
}

func (c *memoryCache) RegisterMetricsTo(r prometheus.Registerer) error {
	return regMetrics(r, c.getTotal, c.hitTotal)
}

func (c *memoryCache) Store(q *dnsmsg.Question, mark uint32, storedTime, expireTime time.Time, v []byte) {
	cost := q.Name.Len() + 4 + len(v) // TODO: Better cost calculation.
	key := hashReq(q, mark)

	qCopy := q.Copy()
	vCopy := copyBuf(v)
	e := newCacheEntry()
	e.l.Lock()
	e.ipMark = mark
	e.storedTime = storedTime
	e.expireTime = expireTime
	e.q = qCopy
	e.v = vCopy
	e.l.Unlock()
	c.backend.SetWithTTL(key, e, int64(cost), time.Until(expireTime))
}

func (c *memoryCache) Get(q *dnsmsg.Question, mark uint32) (resp *dnsmsg.Msg, storedTime, expireTime time.Time) {
	sameQuestion := func(n1, n2 *dnsmsg.Question) bool {
		return n1.Class == n2.Class && n1.Type == n2.Type && bytes.Equal(n1.Name.B(), n2.Name.B())
	}
	c.getTotal.Inc()

	key := hashReq(q, mark)
	e, ok := c.backend.Get(key)
	if ok { // key hit
		if e.l.TryRLock() {
			if e.q == nil {
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{} // entry has been released
			}
			if e.ipMark != mark || !sameQuestion(q, e.q) {
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{} // collision, or entry was reused just now.
			}
			resp, err := unpackCacheMsg(e.v.B())
			e.l.RUnlock()
			if err != nil {
				c.logger.Error("failed to unpack msg", zap.Error(err))
			}
			c.hitTotal.Inc()
			return resp, e.storedTime, e.expireTime
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
	ipMark     uint32
	q          *dnsmsg.Question // nil if released
	v          *pool.Buffer     // nil if released
}

var cacheEntryPool = sync.Pool{
	New: func() any { return new(cacheEntry) },
}

func newCacheEntry() *cacheEntry {
	return cacheEntryPool.Get().(*cacheEntry)
}

func releaseEntry(e *cacheEntry) {
	e.l.Lock()
	dnsmsg.ReleaseQuestion(e.q)
	pool.ReleaseBuf(e.v)
	e.storedTime = time.Time{}
	e.expireTime = time.Time{}
	e.ipMark = 0
	e.q = nil
	e.v = nil
	e.l.Unlock()
	cacheEntryPool.Put(e)
}
