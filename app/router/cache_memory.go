package router

import (
	"bytes"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/dgraph-io/ristretto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type memoryCache struct {
	backend *ristretto.Cache[uint64, *cacheEntry]
	logger  *zerolog.Logger

	getTotal prometheus.Counter
	hitTotal prometheus.Counter
}

func newMemoryCache(size int64, logger *zerolog.Logger) (*memoryCache, error) {
	if logger == nil {
		logger = mlog.Nop()
	}
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

func (c *memoryCache) Store(q *dnsmsg.Question, mark string, storedTime, expireTime time.Time, v []byte) {
	nameLen := q.Name.PackLen()
	cost := nameLen + 4 + len(v) // TODO: Better cost calculation.
	key := hashReq(q, mark)

	nameCopy := copyBuf(q.Name)
	vCopy := copyBuf(v)
	e := newCacheEntry()
	e.l.Lock()
	e.storedTime = storedTime
	e.expireTime = expireTime
	e.ipMark = mark
	e.name = dnsmsg.Name(nameCopy)
	e.typ = q.Type
	e.cls = q.Class
	e.v = vCopy
	e.l.Unlock()
	c.backend.SetWithTTL(key, e, int64(cost), time.Until(expireTime))
}

func (c *memoryCache) Get(q *dnsmsg.Question, mark string) (resp *dnsmsg.Msg, storedTime, expireTime time.Time) {
	c.getTotal.Inc()
	hashKey := hashReq(q, mark)
	e, ok := c.backend.Get(hashKey)
	if ok { // key hit
		if e.l.TryRLock() {
			if e.name == nil {
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{} // entry has been released
			}
			sameReq := e.ipMark == mark &&
				e.typ == q.Type &&
				e.cls == q.Class &&
				bytes.Equal(q.Name, e.name)
			if !sameReq {
				e.l.RUnlock()
				return nil, time.Time{}, time.Time{} // collision, or entry was reused just now.
			}
			resp, err := unpackCacheMsg(e.v)
			storedTime = e.storedTime
			expireTime = e.expireTime
			e.l.RUnlock()

			if err != nil {
				c.backend.Del(hashKey)
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

	ipMark string
	name   dnsmsg.Name // nil if released
	typ    dnsmsg.Type
	cls    dnsmsg.Class

	v pool.Buffer // nil if released
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
	e.ipMark = ""
	dnsmsg.ReleaseName(e.name)
	e.typ = 0
	e.cls = 0
	pool.ReleaseBuf(e.v)
	e.l.Unlock()
	cacheEntryPool.Put(e)
}
