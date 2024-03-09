package router

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/rueidis"
	"github.com/rs/zerolog"
)

type redisCache struct {
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
}

type redisSetOp struct {
	k     pool.Buffer
	v     pool.Buffer
	ttlMs int64
}

func newRedisCache(u string, logger *zerolog.Logger) (*redisCache, error) {
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

	c := &redisCache{
		client:      client,
		logger:      logger,
		setOpChan:   make(chan redisSetOp, 128),
		closeNotify: make(chan struct{}),
	}

	c.getTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_redis_get_total",
		Help: "The total number of get ops",
	})
	c.getLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cache_redis_get_latency_millisecond",
		Help:    "The get op latency in millisecond",
		Buckets: []float64{1, 5, 10, 20, 50, 100},
	})
	c.hitTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_redis_hit_total",
		Help: "The total number of get ops that returned a value (hit the cache)",
	})
	c.setTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_redis_set_total",
		Help: "The total number of set ops",
	})
	c.setLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cache_redis_set_latency_millisecond",
		Help:    "The get set latency in millisecond",
		Buckets: []float64{1, 5, 10, 20, 50, 100},
	})
	c.setDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_redis_set_dropped_total",
		Help: "The total number of set ops that are dropped because the redis server is too slow",
	})

	go c.setLoop()
	go c.pingLoop()
	return c, nil
}

func (c *redisCache) RegisterMetricsTo(r prometheus.Registerer) error {
	return regMetrics(r, c.getTotal, c.getLatency, c.hitTotal, c.setTotal, c.setLatency, c.setDroppedTotal)
}

// Always returns nil.
func (c *redisCache) Close() error {
	c.closeOnce.Do(func() {
		c.client.Close()
		close(c.closeNotify)
	})
	return nil
}

func (c *redisCache) buildKey(q *dnsmsg.Question, marker string) pool.Buffer {
	b := pool.GetBuf(q.Name.PackLen() + 4 + len(marker))
	off := copy(b, pool.Buffer(q.Name))
	binary.BigEndian.PutUint16(b[off:], uint16(q.Class))
	off += 2
	binary.BigEndian.PutUint16(b[off:], uint16(q.Type))
	off += 2
	copy(b[off:], []byte(marker))
	return b
}

func (c *redisCache) buildValue(storedTime, expireTime time.Time, v []byte) pool.Buffer {
	b := pool.GetBuf(16 + len(v))
	binary.BigEndian.PutUint64(b, uint64(storedTime.Unix()))
	binary.BigEndian.PutUint64(b[8:], uint64(expireTime.Unix()))
	copy(b[16:], v)
	return b
}

// Get dose not return error.
// All errors (of broking/invalid stored data, connection lost) will be logged.
func (c *redisCache) Get(ctx context.Context,
	q *dnsmsg.Question,
	mark string) (storedTime, expireTime time.Time,
	resp *dnsmsg.Msg, v []byte) {

	if !c.connected.Load() {
		return
	}

	key := c.buildKey(q, mark)
	defer pool.ReleaseBuf(key)
	start := time.Now()
	cmd := c.client.B().Get().Key(rueidis.BinaryString(key)).Build()
	res := c.client.Do(ctx, cmd)
	b, err := res.AsBytes()
	if err != nil {
		if errors.Is(err, rueidis.Nil) { // miss
			c.getTotal.Inc()
			c.getLatency.Observe(float64(time.Since(start).Milliseconds()))
		} else {
			// This is a redis io error.
			c.logger.Error().Err(err).Msg("get cmd failed")
		}
		return time.Time{}, time.Time{}, nil, nil
	}

	// hit
	if len(b) < 16 {
		c.logger.Error().Msg("invalid cache data, too short")
		return time.Time{}, time.Time{}, nil, nil
	}
	storedTime = time.Unix(int64(binary.BigEndian.Uint64(b[:8])), 0)
	expireTime = time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)
	v = b[16:]

	resp, err = unpackCacheMsg(v)
	if err != nil {
		c.logger.Error().Err(err).Msg("invalid cache data, failed to unpack")
		return
	}

	c.getTotal.Inc()
	c.hitTotal.Inc()
	c.getLatency.Observe(float64(time.Since(start).Milliseconds()))
	return
}

func (c *redisCache) AsyncStore(q *dnsmsg.Question, mark string, storedTime, expireTime time.Time, v []byte) {
	if !c.connected.Load() {
		return
	}

	ttlMs := time.Until(expireTime).Milliseconds()
	if ttlMs <= 10 {
		return
	}

	key := c.buildKey(q, mark)
	value := c.buildValue(storedTime, expireTime, v)
	select {
	case c.setOpChan <- redisSetOp{k: key, v: value, ttlMs: ttlMs}:
	default:
		pool.ReleaseBuf(key)
		pool.ReleaseBuf(value)
		c.setDroppedTotal.Inc()
	}
}

func (c *redisCache) pingLoop() {
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

func (c *redisCache) setLoop() {
	for {
		select {
		case <-c.closeNotify:
			return
		case op := <-c.setOpChan:
			start := time.Now()
			cmd := c.client.B().Set().Key(rueidis.BinaryString(op.k)).Value(rueidis.BinaryString(op.v)).PxMilliseconds(op.ttlMs).Build()
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
