package router

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/rueidis"
	"go.uber.org/zap"
)

type redisCache struct {
	client rueidis.Client
	logger *zap.Logger

	disabled atomic.Bool

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
	k     *pool.Buffer
	v     *pool.Buffer
	ttlMs int64
}

func newRedisCache(u string, logger *zap.Logger) (*redisCache, error) {
	opt, err := rueidis.ParseURL(u)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url, %w", err)
	}
	client, err := rueidis.NewClient(opt)
	if err != nil {
		return nil, err
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		info, err := client.Do(ctx, client.B().Info().Build()).ToString()
		cancel()
		if err != nil {
			logger.Error("redis server ping check failed", zap.Error(err))
		} else {
			fs := []zap.Field{
				zap.Duration("latency", time.Since(start)),
			}
			fs = parseRedisBasicInfo(info, fs)
			logger.Info(
				"redis server connected",
				fs...,
			)
		}
	}()

	c := &redisCache{
		client:      client,
		logger:      logger,
		setOpChan:   make(chan redisSetOp, 16),
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

func (c *redisCache) buildKey(q *dnsmsg.Question, marker uint32) *pool.Buffer {
	b := pool.GetBuf(q.Name.Len() + 8)
	off := copy(b.B(), q.Name.B())
	binary.BigEndian.PutUint16(b.B()[off:], uint16(q.Class))
	off += 2
	binary.BigEndian.PutUint16(b.B()[off:], uint16(q.Type))
	off += 2
	binary.BigEndian.PutUint32(b.B()[off:], marker)
	return b
}

func (c *redisCache) buildValue(storedTime, expireTime time.Time, v []byte) *pool.Buffer {
	b := pool.GetBuf(16 + len(v))
	binary.BigEndian.PutUint64(b.B(), uint64(storedTime.Unix()))
	binary.BigEndian.PutUint64(b.B()[8:], uint64(expireTime.Unix()))
	copy(b.B()[16:], v)
	return b
}

// Returned error is redis connection error.
// The error of broking/invalid stored data will be logged.
func (c *redisCache) Get(ctx context.Context, q *dnsmsg.Question, mark uint32) (storedTime, expireTime time.Time, resp *dnsmsg.Msg, v []byte, err error) {
	if c.disabled.Load() {
		return
	}

	key := c.buildKey(q, mark)
	defer pool.ReleaseBuf(key)
	start := time.Now()
	cmd := c.client.B().Get().Key(rueidis.BinaryString(key.B())).Build()
	res := c.client.Do(ctx, cmd)
	b, err := res.AsBytes()
	if err != nil {
		if errors.Is(err, rueidis.Nil) { // miss
			c.getTotal.Inc()
			c.getLatency.Observe(float64(time.Since(start).Milliseconds()))
			err = nil
		}
		// This is a redis io error.
		return time.Time{}, time.Time{}, nil, nil, err
	}

	// hit
	if len(b) < 16 {
		c.logger.Error("invalid redis cache data, too short", zap.Error(err))
		return time.Time{}, time.Time{}, nil, nil, nil
	}
	storedTime = time.Unix(int64(binary.BigEndian.Uint64(b[:8])), 0)
	expireTime = time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)
	v = b[16:]

	resp, err = unpackCacheMsg(v)
	if err != nil {
		c.logger.Error("failed to unpack redis cache data", zap.Error(err))
		return
	}

	c.getTotal.Inc()
	c.hitTotal.Inc()
	c.getLatency.Observe(float64(time.Since(start).Milliseconds()))
	return
}

func (c *redisCache) AsyncStore(q *dnsmsg.Question, marker uint32, storedTime, expireTime time.Time, v []byte) {
	if c.disabled.Load() {
		return
	}

	ttlMs := time.Until(expireTime).Milliseconds()
	if ttlMs <= 10 {
		return
	}

	key := c.buildKey(q, marker)
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
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := c.client.Do(ctx, c.client.B().Ping().Build()).Error()
			cancel()
			if err != nil {
				c.disabled.Store(true)
				c.logger.Check(zap.ErrorLevel, "redis server ping failed").Write(
					zap.Duration("elapsed", time.Since(start)),
					zap.Error(err),
				)
			} else {
				c.disabled.Store(false)
				c.logger.Check(zap.DebugLevel, "redis server ping check successful").Write(
					zap.Duration("latency", time.Since(start)),
				)
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
			cmd := c.client.B().Set().Key(rueidis.BinaryString(op.k.B())).Value(rueidis.BinaryString(op.v.B())).PxMilliseconds(op.ttlMs).Build()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			err := c.client.Do(ctx, cmd).Error()
			cancel()
			pool.ReleaseBuf(op.k)
			pool.ReleaseBuf(op.v)
			if err != nil {
				c.logger.Warn("redis set failed", zap.Error(err))
			} else {
				c.setTotal.Inc()
				c.setLatency.Observe(float64(time.Since(start).Milliseconds()))
			}
		}
	}
}

// "redis_version", "process_id", "redis_mode"
func parseRedisBasicInfo(s string, zfs []zap.Field) []zap.Field {
	fs := strings.Fields(s)
	for _, ss := range fs {
		k, v, ok := strings.Cut(ss, ":")
		if ok {
			switch k {
			case "redis_version", "process_id", "redis_mode":
				zfs = append(zfs, zap.String(k, v))
			}
		}
	}
	return zfs
}
