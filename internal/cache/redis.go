package cache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/rueidis"
	"github.com/rs/zerolog"
)

type RedisCache struct {
	client rueidis.Client
	logger *zerolog.Logger

	connected atomic.Bool

	setOpChan chan redisSetOp

	closeOnce   sync.Once
	closeNotify chan struct{}

	getTotal        prometheus.Counter
	getLatency      prometheus.Histogram
	hitTotal        prometheus.Counter
	setTotal        prometheus.Counter
	setLatency      prometheus.Histogram
	setDroppedTotal prometheus.Counter
	pingLatency     prometheus.Histogram
}

type redisSetOp struct {
	k     pool.Buffer
	v     pool.Buffer
	ttlMs int64
	nx    bool
}

func NewRedisCache(u string, logger *zerolog.Logger) (*RedisCache, error) {
	if logger == nil {
		logger = mlog.Nop()
	}
	opt, err := rueidis.ParseURL(u)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url, %w", err)
	}
	client, err := rueidis.NewClient(opt)
	if err != nil {
		return nil, err
	}

	c := &RedisCache{
		client:      client,
		logger:      logger,
		setOpChan:   make(chan redisSetOp, 128),
		closeNotify: make(chan struct{}),
	}

	c.getTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "get_total",
		Help: "The total number of GET cmd",
	})
	c.getLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "get_latency_millisecond",
		Help:    "The GET cmd latency in millisecond",
		Buckets: []float64{1, 5, 10, 20},
	})
	c.hitTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hit_total",
		Help: "The total number of GET cmd that returned a value (hit the cache)",
	})
	c.setTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "set_total",
		Help: "The total number of SET cmd",
	})
	c.setLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "set_latency_millisecond",
		Help:    "The SET cmd latency in millisecond",
		Buckets: []float64{1, 5, 10, 20},
	})
	c.setDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "set_dropped_total",
		Help: "The total number of SET cmd that are dropped because the redis server is too slow",
	})
	c.pingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ping_latency_millisecond",
		Help:    "The PING cmd latency in millisecond",
		Buckets: []float64{1, 5, 10, 20},
	})
	go c.setLoop()
	go c.pingLoop()
	return c, nil
}

func (c *RedisCache) Collectors() []prometheus.Collector {
	return []prometheus.Collector{c.getTotal, c.getLatency, c.hitTotal, c.setTotal, c.setLatency, c.setDroppedTotal, c.pingLatency}
}

// Always returns nil.
func (c *RedisCache) Close() error {
	c.closeOnce.Do(func() {
		c.client.Close()
		close(c.closeNotify)
	})
	return nil
}

func (c *RedisCache) buildValue(storedTime, expireTime time.Time, v []byte) pool.Buffer {
	b := pool.GetBuf(16 + len(v))
	binary.BigEndian.PutUint64(b, uint64(storedTime.Unix()))
	binary.BigEndian.PutUint64(b[8:], uint64(expireTime.Unix()))
	copy(b[16:], v)
	return b
}

// Get dose not return error.
// All errors (of broking/invalid stored data, connection lost, etc.) will be logged.
func (c *RedisCache) Get(ctx context.Context, k []byte) (storedTime, expireTime time.Time, v []byte) {
	if !c.connected.Load() {
		return
	}

	start := time.Now()
	res := c.client.Do(ctx, c.client.B().Get().Key(rueidis.BinaryString(k)).Build())
	b, err := res.AsBytes()
	if err != nil {
		if errors.Is(err, rueidis.Nil) { // miss
			c.getTotal.Inc()
			c.getLatency.Observe(float64(time.Since(start).Milliseconds()))
		} else {
			// This is a redis io/type error.
			c.logger.Error().Err(err).Msg("get cmd failed")
		}
		return time.Time{}, time.Time{}, nil
	}

	// hit
	if len(b) < 16 {
		c.logger.Error().Msg("invalid cache data, too short")
		// TODO: Delete this invalid key here?
		return time.Time{}, time.Time{}, nil
	}
	c.getTotal.Inc()
	c.hitTotal.Inc()
	c.getLatency.Observe(float64(time.Since(start).Milliseconds()))

	storedTime = time.Unix(int64(binary.BigEndian.Uint64(b[:8])), 0)
	expireTime = time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)
	v = b[16:]
	return
}

// Store v in to redis asynchronously.
func (c *RedisCache) AsyncStore(k []byte, storedTime, expireTime time.Time, v []byte, setNX bool) {
	if !c.connected.Load() {
		return
	}

	ttlMs := time.Until(expireTime).Milliseconds()
	if ttlMs <= 10 {
		return
	}

	key := pool.CopyBuf(k)
	value := c.buildValue(storedTime, expireTime, v)
	select {
	case c.setOpChan <- redisSetOp{k: key, v: value, ttlMs: ttlMs, nx: setNX}:
	default:
		pool.ReleaseBuf(key)
		pool.ReleaseBuf(value)
		c.setDroppedTotal.Inc()
	}
}

func (c *RedisCache) pingLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeNotify:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			start := time.Now()
			err := c.client.Do(ctx, c.client.B().Ping().Build()).Error()
			elapse := time.Since(start)
			cancel()
			if err != nil {
				c.connected.Store(false)
				c.logger.Error().
					Err(err).
					Dur("elapse", elapse).
					Msg("redis server ping lost")
			} else {
				c.pingLatency.Observe(float64(elapse.Milliseconds()))
				if prevConnected := c.connected.Swap(true); !prevConnected {
					c.logger.Info().Dur("latency", elapse).
						Msg("redis server connected")
				} else {
					c.logger.Debug().Dur("latency", elapse).
						Msg("redis server ping")
				}
			}
		}
	}
}

func (c *RedisCache) setLoop() {
	for {
		select {
		case <-c.closeNotify:
			return
		case op := <-c.setOpChan:
			start := time.Now()

			var cmd rueidis.Completed
			if op.nx {
				cmd = c.client.B().Set().Key(rueidis.BinaryString(op.k)).Value(rueidis.BinaryString(op.v)).Nx().PxMilliseconds(op.ttlMs).Build()
			} else {
				cmd = c.client.B().Set().Key(rueidis.BinaryString(op.k)).Value(rueidis.BinaryString(op.v)).PxMilliseconds(op.ttlMs).Build()
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			err := c.client.Do(ctx, cmd).Error()
			cancel()
			pool.ReleaseBuf(op.k)
			pool.ReleaseBuf(op.v)
			if err != nil {
				c.logger.Err(err).Msg("redis set cmd failed")
			} else {
				c.setTotal.Inc()
				c.setLatency.Observe(float64(time.Since(start).Milliseconds()))
			}
		}
	}
}
