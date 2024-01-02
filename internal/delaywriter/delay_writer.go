package delaywriter

import (
	"bufio"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultDelay = time.Millisecond * 1
)

var ErrClosedDelayWriter = errors.New("closed delay writer")

type DelayWriter struct {
	l                   sync.Mutex
	w                   io.Writer
	bw                  *bufio.Writer
	directW             *rate.Limiter // maybe nil
	latestAsyncFlushErr error
	asyncFlushNotify    chan struct{}
	closeNotify         chan struct{}
	closed              bool
}

type Opts struct {
	BufSize              int
	Delay                time.Duration
	DirectWriteRateLimit rate.Limit
	DirectWriteBursts    int
}

// return nil if r <= 0
func newRateLimiterOrNil(r rate.Limit, b int) *rate.Limiter {
	if r <= 0 {
		return nil
	}
	return rate.NewLimiter(r, b)
}

func New(w io.Writer, opts Opts) *DelayWriter {
	dw := &DelayWriter{
		w:                w,
		bw:               bufio.NewWriterSize(w, opts.BufSize),
		directW:          newRateLimiterOrNil(opts.DirectWriteRateLimit, opts.DirectWriteBursts),
		asyncFlushNotify: make(chan struct{}, 1),
		closeNotify:      make(chan struct{}, 1),
	}
	go dw.asyncFlushLoop(opts.Delay)
	return dw
}

func (c *DelayWriter) Write(b []byte) (n int, err error) {
	c.l.Lock()
	defer c.l.Unlock()

	if c.closed {
		return 0, ErrClosedDelayWriter
	}

	// Notify caller that latest async flush call failed.
	if err = c.latestAsyncFlushErr; err != nil {
		c.latestAsyncFlushErr = nil
		return 0, err
	}

	if c.directW != nil && c.directW.Allow() {
		err := c.bw.Flush()
		if err != nil {
			return 0, err
		}
		return c.w.Write(b)
	}

	n, err = c.bw.Write(b)
	if err != nil {
		return n, err
	}
	if c.bw.Buffered() > 0 {
		select {
		case c.asyncFlushNotify <- struct{}{}:
		default:
		}
	}
	return len(b), nil
}

func (c *DelayWriter) Flush() error {
	c.l.Lock()
	defer c.l.Unlock()

	if c.closed {
		return ErrClosedDelayWriter
	}
	return c.bw.Flush()
}

func (c *DelayWriter) Sync() error {
	return c.Flush()
}

func (c *DelayWriter) asyncFlushLoop(delay time.Duration) {
	if delay <= 0 {
		delay = defaultDelay
	}
	delayTimer := time.NewTimer(defaultDelay)
	defer delayTimer.Stop()

	for {
		select {
		case <-c.closeNotify:
			return
		case <-c.asyncFlushNotify:
			delayTimer.Reset(defaultDelay)
			select {
			case <-c.closeNotify:
				return
			case <-delayTimer.C:
				delayTimer.Reset(defaultDelay)
				<-delayTimer.C
				c.l.Lock()
				c.latestAsyncFlushErr = c.bw.Flush()
				c.l.Unlock()
			}
		}
	}
}

func (c *DelayWriter) Close() error {
	c.l.Lock()
	defer c.l.Unlock()

	if c.closed {
		return ErrClosedDelayWriter
	}
	c.closed = true
	close(c.closeNotify)
	return c.bw.Flush()
}
