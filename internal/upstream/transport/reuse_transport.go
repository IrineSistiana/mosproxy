package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

const (
	// Most servers will send SERVFAIL after 3~5s. If no resp, connection may be dead.
	reuseConnQueryTimeout = time.Second * 6
)

var _ Transport = (*ReuseConnTransport)(nil)

// ReuseConnTransport is for old tcp protocol. (no pipelining)
type ReuseConnTransport struct {
	opts        ReuseConnOpts
	ctx         context.Context
	cancelCause context.CancelCauseFunc
	logger      *zerolog.Logger // non-nil

	m         sync.Mutex // protect following fields
	closed    bool
	idleConns map[*reusableConn]struct{}
	conns     map[*reusableConn]struct{}

	// for testing
	testRespTimeout time.Duration
}

type ReuseConnOpts struct {
	// DialContext specifies the method to dial a connection to the server.
	// DialContext MUST NOT be nil.
	DialContext func(ctx context.Context) (net.Conn, error)

	// DialTimeout specifies the timeout for DialFunc.
	// Default is defaultDialTimeout.
	DialTimeout time.Duration

	// Default is defaultIdleTimeout
	IdleTimeout time.Duration

	Logger *zerolog.Logger
}

func NewReuseConnTransport(opts ReuseConnOpts) *ReuseConnTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &ReuseConnTransport{
		opts:        opts,
		ctx:         ctx,
		cancelCause: cancel,
		logger:      nonNilLogger(opts.Logger),
		idleConns:   make(map[*reusableConn]struct{}),
		conns:       make(map[*reusableConn]struct{}),
	}
	return t
}

func (t *ReuseConnTransport) dialTimeout() time.Duration {
	return defaultIfLeZero(t.opts.DialTimeout, defaultDialTimeout)
}

// Note: context is not impl while waiting resp. The timeout is hardcoded, which is reuseConnQueryTimeout.
func (t *ReuseConnTransport) ExchangeContext(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	if len(m) < dnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}
	payload, err := copyMsgWithLenHdr(m)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(payload)

	errs := make([]error, 0)
	retry := 0
	for {
		var isNewConn bool
		c, err := t.getIdleConn()
		if err != nil {
			errs = append(errs, err)
			return nil, joinErr(errs)
		}
		if c == nil {
			isNewConn = true
			c, err = t.asyncDial(ctx)
			if err != nil {
				errs = append(errs, err)
				return nil, joinErr(errs)
			}
		}

		resp, err := t.exchangeConnCtx(ctx, payload, c)
		if err != nil {
			errs = append(errs, err)
			if !isNewConn && retry <= 5 && !ctxIsDone(ctx) {
				retry++
				continue // retry if c is a reused connection.
			}
			return nil, joinErr(errs)
		}
		return resp, nil
	}
}

// Note: c will be put back to the pool.
func (t *ReuseConnTransport) exchangeConnCtx(ctx context.Context, payload []byte, c *reusableConn) (*dnsmsg.Msg, error) {
	type res struct {
		m   *dnsmsg.Msg
		err error
	}
	resChan := make(chan res, 1)

	go func() {
		resp, err := t.exchangeConn(payload, c)
		resChan <- res{m: resp, err: err}
		t.releaseConn(c, err)
	}()
	select {
	case r := <-resChan:
		return r.m, r.err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (t *ReuseConnTransport) exchangeConn(payload []byte, c *reusableConn) (*dnsmsg.Msg, error) {
	respTimeout := reuseConnQueryTimeout
	if t.testRespTimeout > 0 {
		respTimeout = t.testRespTimeout
	}
	c.c.SetDeadline(time.Now().Add(respTimeout))
	_, err := c.c.Write(payload)
	if err != nil {
		return nil, err
	}
	r, _, err := dnsutils.ReadMsgFromTCP(c.c)
	return r, err
}

func (t *ReuseConnTransport) releaseConn(rc *reusableConn, err error) {
	if err != nil {
		debugLogTransportConnClosed(rc.c, t.logger, err)
		rc.close()
	} else {
		rc.enterIdle()
	}

	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		if err == nil {
			rc.close()
		}
		return
	}
	if err != nil {
		delete(t.conns, rc)
	} else {
		t.idleConns[rc] = struct{}{}
	}
	t.m.Unlock()
}

// asyncDial dial a *reusableConn.
func (t *ReuseConnTransport) asyncDial(ctx context.Context) (*reusableConn, error) {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialRes struct {
		c   *reusableConn
		err error
	}
	dialChan := make(chan dialRes)
	go func() {
		dialCtx, cancelDial := context.WithTimeout(t.ctx, t.dialTimeout())
		defer cancelDial()

		c, err := t.opts.DialContext(dialCtx)
		if err != nil {
			t.logger.Warn().
				Err(err).
				Msg("failed to dial conn")
		}

		var rc *reusableConn
		if c != nil {
			rc = newReusableConn(c, t.opts.IdleTimeout)
			rc.exitIdle()
			t.m.Lock()
			if t.closed {
				t.m.Unlock()
				rc.close()
				rc = nil
				err = ErrClosedTransport
			} else {
				t.conns[rc] = struct{}{}
				t.m.Unlock()
				debugLogTransportConnOpen(c, t.logger)
			}
		}

		select {
		case dialChan <- dialRes{c: rc, err: err}:
		case <-callCtx.Done(): // caller canceled getNewConn() call
			if rc != nil {
				t.releaseConn(rc, nil)
			}
		}
	}()

	select {
	case <-callCtx.Done():
		return nil, context.Cause(ctx)
	case res := <-dialChan:
		return res.c, res.err
	}
}

// getIdleConn returns a *reusableConn from conn pool, or nil if no conn
// is idle.
func (t *ReuseConnTransport) getIdleConn() (*reusableConn, error) {
	t.m.Lock()
	defer t.m.Unlock()
	if t.closed {
		return nil, ErrClosedTransport
	}

	for c := range t.idleConns {
		delete(t.idleConns, c)
		if closed := c.exitIdle(); closed {
			delete(t.conns, c)
			continue
		}
		return c, nil
	}
	return nil, nil
}

// Close closes ReuseConnTransport and all its connections.
// It always returns a nil error.
func (t *ReuseConnTransport) Close() error {
	t.m.Lock()
	defer t.m.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	for c := range t.conns {
		c.c.Close()
	}
	t.cancelCause(ErrClosedTransport)
	return nil
}

type reusableConn struct {
	c           net.Conn
	idleTimeout time.Duration

	m         sync.Mutex
	serving   bool
	closed    bool
	idleTimer *time.Timer
}

func newReusableConn(c net.Conn, idleTimeout time.Duration) *reusableConn {
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	rc := &reusableConn{
		c:           c,
		idleTimeout: idleTimeout,
	}
	rc.idleTimer = time.AfterFunc(idleTimeout, rc.closeIfIdle)
	return rc
}

func (c *reusableConn) exitIdle() (closed bool) {
	c.m.Lock()
	defer c.m.Unlock()
	if c.closed {
		return true
	}
	if c.serving {
		panic("call exitIdle on a busy connection")
	}
	c.serving = true
	c.idleTimer.Stop()
	err := c.c.SetReadDeadline(time.Time{}) // Fast check if connection has been closed.
	return err != nil
}

func (c *reusableConn) enterIdle() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.serving {
		panic("call enterIdle on a idle connection")
	}
	c.serving = false
	c.idleTimer.Reset(c.idleTimeout)
}

func (c *reusableConn) closeIfIdle() {
	c.m.Lock()
	serving := c.serving
	if !serving {
		c.closed = true
		defer c.c.Close()
	}
	c.m.Unlock()
}

func (c *reusableConn) close() {
	c.m.Lock()
	if c.closed {
		c.m.Unlock()
		return
	}
	c.closed = true
	c.idleTimer.Stop()
	c.m.Unlock()
	c.c.Close()
}
