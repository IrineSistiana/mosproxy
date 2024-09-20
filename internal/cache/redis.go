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

func (c *RedisCache) buildValue(v []byte, t Times) pool.Buffer {
	b := pool.GetBuf(24 + len(v))
	binary.BigEndian.PutUint64(b[0:8], uint64(t.StoredAtUnix))
	binary.BigEndian.PutUint64(b[8:16], uint64(t.ExpireAtUnix))
	binary.BigEndian.PutUint64(b[16:24], uint64(t.CacheExpireAtUnix))
	copy(b[24:], v)
	return b
}

// Get dose not return error.
// All errors (of broking/invalid stored data, connection lost, etc.) will be logged.
func (c *RedisCache) Get(ctx context.Context, k []byte) ([]byte, Times) {
	if !c.backendOnline.Load() {
		return nil, Times{}
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
		return nil, Times{}
	}

	// hit
	if len(b) < 24 {
		c.logger.Error().Msg("invalid cache data, too short")
		// TODO: Delete this invalid key here?
		return nil, Times{}
	}
	c.getTotal.Inc()
	c.hitTotal.Inc()
	c.getLatency.Observe(float64(time.Since(start).Milliseconds()))

	t := Times{
		StoredAtUnix:      int64(binary.BigEndian.Uint64(b[:8])),
		ExpireAtUnix:      int64(binary.BigEndian.Uint64(b[8:16])),
		CacheExpireAtUnix: int64(binary.BigEndian.Uint64(b[16:24])),
	}
	v := b[24:]
	return v, t
}

// Store v in to redis.
// Errors will be logged to the RedisCache logger.
func (c *RedisCache) Store(k []byte, v []byte, t Times, setNX bool) {
	if !c.backendOnline.Load() {
		return
	}

	if time.Now().Unix() >= t.CacheExpireAtUnix {
		return
	}

	data := c.buildValue(v, t)
	defer pool.ReleaseBuf(data)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()

	start := time.Now()
	var cmd rueidis.Completed
	if setNX {
		cmd = c.client.B().Set().Key(rueidis.BinaryString(k)).Value(rueidis.BinaryString(data)).Nx().ExatTimestamp(t.CacheExpireAtUnix).Build()
	} else {
		cmd = c.client.B().Set().Key(rueidis.BinaryString(k)).Value(rueidis.BinaryString(data)).ExatTimestamp(t.CacheExpireAtUnix).Build()
	}
	err := c.client.Do(ctx, cmd).Error()
	if err != nil && !errors.Is(err, rueidis.Nil) { // NX may response a Nil reply if key exists.
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
