package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap"
)

const (
	// Most servers will send SERVFAIL after 3~5s. If no resp, connection may be dead.
	reuseConnQueryTimeout = time.Second * 6
)

var _ Transport = (*ReuseConnTransport)(nil)

// ReuseConnTransport is for old tcp protocol. (no pipelining)
type ReuseConnTransport struct {
	ctx         context.Context
	cancel      context.CancelCauseFunc
	dialFunc    func(ctx context.Context) (net.Conn, error)
	dialTimeout time.Duration
	idleTimeout time.Duration
	logger      *zap.Logger // non-nil

	m         sync.Mutex // protect following fields
	closed    bool
	idleConns map[*reusableConn]struct{}
	conns     map[*reusableConn]struct{}

	// for testing
	testWaitRespTimeout time.Duration
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

	Logger *zap.Logger
}

func NewReuseConnTransport(opt ReuseConnOpts) *ReuseConnTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &ReuseConnTransport{
		ctx:       ctx,
		cancel:    cancel,
		idleConns: make(map[*reusableConn]struct{}),
		conns:     make(map[*reusableConn]struct{}),
	}
	t.dialFunc = opt.DialContext
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, defaultDialTimeout)
	setDefaultGZ(&t.idleTimeout, opt.IdleTimeout, defaultIdleTimeout)
	setNonNilLogger(&t.logger, opt.Logger)

	return t
}

// Note: context is not impl while waiting resp. The timeout is hardcoded, which is reuseConnQueryTimeout.
func (t *ReuseConnTransport) ExchangeContext(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	const maxRetry = 5

	if len(m) < dnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}
	payload, err := copyMsgWithLenHdr(m)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(payload)

	retry := 0
	for {
		var isNewConn bool
		c, err := t.getIdleConn()
		if err != nil {
			return nil, err
		}
		if c == nil {
			isNewConn = true
			c, err = t.asyncDial(ctx)
			if err != nil {
				return nil, err
			}
		}

		resp, err := t.exchangeConn(payload.B(), c)
		t.releaseConn(c, err)
		if err != nil {
			if !isNewConn && retry <= maxRetry && !ctxIsDone(ctx) {
				retry++
				continue // retry if c is a reused connection.
			}
			return nil, err
		}
		return resp, nil
	}
}

func (t *ReuseConnTransport) exchangeConn(payload []byte, c *reusableConn) (*dnsmsg.Msg, error) {
	waitRespTimeout := reuseConnQueryTimeout
	if t.testWaitRespTimeout > 0 {
		waitRespTimeout = t.testWaitRespTimeout
	}
	c.c.SetDeadline(time.Now().Add(waitRespTimeout))
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
		rc.c.Close()
	}

	t.m.Lock()
	defer t.m.Unlock()
	if err != nil {
		delete(t.conns, rc)
	} else {
		t.idleConns[rc] = struct{}{}
	}
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
		dialCtx, cancelDial := context.WithTimeout(t.ctx, t.dialTimeout)
		defer cancelDial()

		c, err := t.dialFunc(dialCtx)
		if err != nil {
			t.logger.Check(zap.WarnLevel, "fail to dial reusable conn").Write(zap.Error(err))
		}

		var rc *reusableConn
		if c != nil {
			t.m.Lock()
			if t.closed {
				t.m.Unlock()
				c.Close()
				err = ErrClosedTransport
			} else {
				rc = &reusableConn{c: c}
				t.conns[rc] = struct{}{}
				t.m.Unlock()
				debugLogTransportNewConn(c, t.logger)
			}
		}

		select {
		case dialChan <- dialRes{c: rc, err: err}:
		case <-callCtx.Done(): // caller canceled getNewConn() call
			if rc != nil { // put this conn to pool
				t.m.Lock()
				if t.closed {
					t.m.Unlock()
				} else {
					t.idleConns[rc] = struct{}{}
					t.m.Unlock()
				}
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
// The caller must call *reusableConn.exchange() once.
func (t *ReuseConnTransport) getIdleConn() (*reusableConn, error) {
	t.m.Lock()
	defer t.m.Unlock()
	if t.closed {
		return nil, ErrClosedTransport
	}

	for c := range t.idleConns {
		delete(t.idleConns, c)
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
	t.cancel(ErrClosedTransport)
	return nil
}

type reusableConn struct {
	c net.Conn
}
