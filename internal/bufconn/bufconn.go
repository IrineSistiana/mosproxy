package bufconn

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var highThroughputMode = func() bool {
	ok, _ := strconv.ParseBool(os.Getenv("MOSPROXY_TCP_HTM"))
	return ok
}()

const (
	defaultDelayWriteDuration = time.Millisecond * 1
)

type BufConn struct {
	c net.Conn

	rl sync.Mutex
	r  *bufio.Reader // maybe nil

	wl             sync.Mutex
	w              *bufio.Writer // maybe nil
	latestFlushErr error
	flushNotify    chan struct{}
	closeNotify    chan struct{}
	closeOnce      sync.Once
}

type Opts struct {
	ReadBufSize, WriteBufSize int
	DelayWriteDuration        time.Duration
}

func New(c net.Conn) *BufConn {
	wb := 0
	if highThroughputMode {
		wb = 1024
	}
	return NewOpts(c, Opts{ReadBufSize: 1024, WriteBufSize: wb})
}

func NewOpts(c net.Conn, opts Opts) *BufConn {
	bc := &BufConn{
		c: c,
	}

	if opts.ReadBufSize > 0 {
		bc.r = bufio.NewReaderSize(c, opts.ReadBufSize)
	}
	if opts.WriteBufSize > 0 {
		bc.w = bufio.NewWriterSize(c, opts.WriteBufSize)
		bc.flushNotify = make(chan struct{}, 1)
		bc.closeNotify = make(chan struct{})
		go bc.asyncFlushLoop(opts.DelayWriteDuration)
	}
	return bc
}

func (c *BufConn) Read(b []byte) (n int, err error) {
	if c.r == nil {
		return c.c.Read(b)
	}

	c.rl.Lock()
	defer c.rl.Unlock()
	return c.r.Read(b)
}

func (c *BufConn) Write(b []byte) (n int, err error) {
	if c.w == nil {
		return c.c.Write(b)
	}

	c.wl.Lock()
	defer c.wl.Unlock()

	// Notify caller that latest flush call failed.
	if err = c.latestFlushErr; err != nil {
		c.latestFlushErr = nil
		return 0, err
	}

	n, err = c.w.Write(b)
	if err != nil {
		return n, err
	}
	if c.w.Buffered() > 0 {
		select {
		case c.flushNotify <- struct{}{}:
		default:
		}
	}
	return len(b), nil
}

func (c *BufConn) Flush() error {
	if c.w == nil {
		return nil
	}

	c.wl.Lock()
	defer c.wl.Unlock()
	return c.w.Flush()
}

func (c *BufConn) asyncFlushLoop(delayWriteDuration time.Duration) {
	if delayWriteDuration <= 0 {
		delayWriteDuration = defaultDelayWriteDuration
	}
	delayTimer := time.NewTimer(defaultDelayWriteDuration)
	defer delayTimer.Stop()
	for {
		select {
		case <-c.closeNotify:
			return
		case <-c.flushNotify:
			delayTimer.Reset(defaultDelayWriteDuration)
			<-delayTimer.C
			c.wl.Lock()
			c.latestFlushErr = c.w.Flush()
			c.wl.Unlock()
		}
	}
}

func (c *BufConn) Close() error {
	var flushErr error
	if c.w != nil {
		c.wl.Lock()
		flushErr = c.w.Flush()
		c.wl.Unlock()
		c.closeOnce.Do(func() { close(c.closeNotify) })
	}
	return errors.Join(flushErr, c.c.Close())
}

func (c *BufConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *BufConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *BufConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *BufConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *BufConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}
