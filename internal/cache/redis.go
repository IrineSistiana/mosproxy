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
	logger *zerolog.Logger // not nil

	backendOnline atomic.Bool

	closeOnce   sync.Once
	closeNotify chan struct{}

	getTotal    prometheus.Counter
	getLatency  prometheus.Histogram
	hitTotal    prometheus.Counter
	setTotal    prometheus.Counter
	setLatency  prometheus.Histogram
	pingLatency prometheus.Histogram
}

func NewRedisCache(u string, logger *zerolog.Logger) (*RedisCache, error) {
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
		closeNotify: make(chan struct{}),
	}
	if c.logger == nil {
		c.logger = mlog.Nop()
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
	c.pingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ping_latency_millisecond",
		Help:    "The PING cmd latency in millisecond",
		Buckets: []float64{1, 5, 10, 20},
	})
	go c.pingLoop()
	return c, nil
}

func (c *RedisCache) Collectors() []prometheus.Collector {
	return []prometheus.Collector{c.getTotal, c.getLatency, c.hitTotal, c.setTotal, c.setLatency, c.pingLatency}
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
	if !c.backendOnline.Load() {
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

// Store v in to redis.
// Errors will be logged to the RedisCache logger.
func (c *RedisCache) Store(k []byte, storedTime, expireTime time.Time, v []byte, setNX bool) {
	if !c.backendOnline.Load() {
		return
	}

	ttlMs := time.Until(expireTime).Milliseconds()
	if ttlMs <= 10 {
		return
	}

	data := c.buildValue(storedTime, expireTime, v)
	defer pool.ReleaseBuf(data)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()

	start := time.Now()
	var cmd rueidis.Completed
	if setNX {
		cmd = c.client.B().Set().Key(rueidis.BinaryString(k)).Value(rueidis.BinaryString(data)).Nx().PxMilliseconds(ttlMs).Build()
	} else {
		cmd = c.client.B().Set().Key(rueidis.BinaryString(k)).Value(rueidis.BinaryString(data)).PxMilliseconds(ttlMs).Build()
	}
	err := c.client.Do(ctx, cmd).Error()
	if err != nil {
		c.logger.Err(err).Msg("redis set cmd failed")
	} else {
		c.setTotal.Inc()
		c.setLatency.Observe(float64(time.Since(start).Milliseconds()))
	}
}

func (c *RedisCache) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	err := c.client.Do(ctx, c.client.B().Ping().Build()).Error()
	elapse := time.Since(start)
	if err != nil {
		c.backendOnline.Store(false)
		c.logger.Error().
			Err(err).
			Dur("elapse", elapse).
			Msg("redis server ping lost")
	} else {
		c.pingLatency.Observe(float64(elapse.Milliseconds()))
		if wasOnline := c.backendOnline.Swap(true); !wasOnline {
			c.logger.Info().Dur("latency", elapse).
				Msg("redis server connected")
		} else {
			c.logger.Debug().Dur("latency", elapse).
				Msg("redis server ping")
		}
	}
	return elapse, err
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
			c.Ping(ctx)
			cancel()
		}
	}
}
