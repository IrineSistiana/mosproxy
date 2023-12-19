package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"go.uber.org/zap"
)

const (
	// If a pipeline connection sent a query but did not see any reply (include replies that
	// for other queries) from the server after pipelineWaitingReplyTimeout. It assumes that
	// something goes wrong with the connection or the server. The connection will be closed.
	pipelineWaitingReplyTimeout = time.Second * 10

	defaultPipelineMaxConcurrent = 32
)

var ErrPpHdrIsNotAllowed = errors.New("msg offset is not allowed in tcp transport")

var _ Transport = (*PipelineTransport)(nil)

// PipelineTransport will pipeline queries as RFC 7766 6.2.1.1 suggested.
// It also can reuse udp socket. Since dns over udp is some kind of "pipeline".
type PipelineTransport struct {
	ctx                      context.Context
	cancelCtx                context.CancelCauseFunc
	dialFunc                 func(ctx context.Context) (net.Conn, error)
	dialTimeout              time.Duration
	connMaxConcurrentQueries int
	connIdleTimeout          time.Duration
	connIsTcp                bool
	logger                   *zap.Logger

	m            sync.Mutex // protect following fields
	closed       bool
	dialingCalls map[*dialingCall]struct{}
	conns        map[*pipelineConn]struct{}
	eols         map[*pipelineConn]struct{}

	_testConnMaxServedQueries uint16
}

type PipelineOpts struct {
	// DialContext specifies the method to dial a connection to the server.
	// DialContext MUST NOT be nil.
	DialContext func(ctx context.Context) (net.Conn, error)

	// DialTimeout specifies the timeout for DialFunc.
	// Default is defaultDialTimeout.
	DialTimeout time.Duration

	// Set to true if underlayer is TCP. Which needs a 2 bytes length header.
	IsTCP bool

	// IdleTimeout controls the maximum idle time for each connection.
	// Default is defaultIdleTimeout.
	IdleTimeout time.Duration

	// MaxConcurrentQuery limits the number of maximum concurrent queries
	// in the connection. Default is defaultPipelineMaxConcurrent.
	MaxConcurrentQuery int

	Logger *zap.Logger
}

func NewPipelineTransport(opt PipelineOpts) *PipelineTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &PipelineTransport{
		ctx:          ctx,
		cancelCtx:    cancel,
		dialingCalls: make(map[*dialingCall]struct{}),
		conns:        make(map[*pipelineConn]struct{}),
		eols:         make(map[*pipelineConn]struct{}),
	}

	t.dialFunc = opt.DialContext
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, defaultDialTimeout)
	setDefaultGZ(&t.connMaxConcurrentQueries, opt.MaxConcurrentQuery, defaultPipelineMaxConcurrent)
	setDefaultGZ(&t.connIdleTimeout, opt.IdleTimeout, defaultIdleTimeout)
	t.connIsTcp = opt.IsTCP
	setNonNilLogger(&t.logger, opt.Logger)
	return t
}

// Spacial exchange call mainly for protocol proxy header.
// t underlayer protocol must be udp.
// It's ok that ppHdr is nil.
func (t *PipelineTransport) ExchangeContextOff(ctx context.Context, ppHdr, m []byte) (*dnsmsg.Msg, error) {
	return t.exchangeContext(ctx, ppHdr, m)
}

func (t *PipelineTransport) ExchangeContext(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	return t.exchangeContext(ctx, nil, m)
}

func (t *PipelineTransport) exchangeContext(ctx context.Context, ppHdr, m []byte) (*dnsmsg.Msg, error) {
	if len(m) < dnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}

	if t.connIsTcp && len(ppHdr) > 0 {
		return nil, ErrPpHdrIsNotAllowed
	}

	start := time.Now()
	retry := 0
	for {
		b, err, shouldRetry := t.exchangeOnce(ctx, ppHdr, m)
		if err != nil && shouldRetry && retry < 3 && time.Since(start) < time.Second && !ctxIsDone(ctx) {
			retry++
			continue
		}
		return b, err
	}
}

func setQid(payload []byte, off int, qid uint16) {
	binary.BigEndian.PutUint16(payload[off:], qid)
}

func (t *PipelineTransport) exchangeOnce(ctx context.Context, ppHdr, m []byte) (_ *dnsmsg.Msg, _ error, shouldRetry bool) {
	call, pc, qid, closed := t.reserveConn()
	if closed {
		return nil, ErrClosedTransport, false
	}

	if call != nil {
		b, err := t.exchangeUsingDialingCall(ctx, ppHdr, m, call)
		call.release()
		shouldRetry = errors.Is(err, ErrTooManyPipeliningQueries)
		return b, err, shouldRetry
	}

	b, err := pc.exchange(ctx, ppHdr, m, qid)
	pc.releaseQid()
	return b, err, true
}

type ErrNoAvailablePipelineConn struct {
	cause error
}

func (e *ErrNoAvailablePipelineConn) Error() string {
	return fmt.Sprintf("failed to get available pipeline conn, %s", e.cause)
}

func (e *ErrNoAvailablePipelineConn) Unwrap() error {
	return e.cause
}

func (t *PipelineTransport) exchangeUsingDialingCall(ctx context.Context, ppHdr, m []byte, call *dialingCall) (*dnsmsg.Msg, error) {
	select {
	case <-ctx.Done():
		return nil, &ErrNoAvailablePipelineConn{cause: context.Cause(ctx)}
	case <-call.done:
		c, err := call.c, call.err
		if err != nil {
			return nil, &ErrNoAvailablePipelineConn{cause: err}
		}
		qid, _, ok := c.reserveQid()
		if !ok {
			return nil, &ErrNoAvailablePipelineConn{cause: ErrTooManyPipeliningQueries}
		}
		defer c.releaseQid()
		return c.exchange(ctx, ppHdr, m, qid)
	}
}

// Note: call (dialingCall|pipelineConn).reservedQueryDone after query finished.
func (t *PipelineTransport) reserveConn() (_ *dialingCall, _ *pipelineConn, qid uint16, closed bool) {
	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		return nil, nil, 0, true
	}

	// try to find an available conn first
	retry := 0
	for c := range t.conns {
		qid, eol, ok := c.reserveQid()
		if eol {
			delete(t.conns, c)
			t.eols[c] = struct{}{}
		}
		if ok {
			t.m.Unlock()
			return nil, c, qid, false
		}
		if retry > 3 {
			break
		}
		retry++
	}

	// then try to find a available dialing call
	retry = 0
	for call := range t.dialingCalls {
		if call.reserve(t.connMaxConcurrentQueries) {
			t.m.Unlock()
			return call, nil, 0, false
		}
		if retry > 3 {
			break
		}
		retry++
	}

	// dial a new conn
	call := &dialingCall{
		done:     make(chan struct{}),
		reserved: 1, // reserve a request in advance
	}
	t.dialingCalls[call] = struct{}{}
	t.m.Unlock()

	go func() {
		t.dial(call)
	}()
	return call, nil, 0, false
}

// Close closes PipelineTransport and all its connections.
// It always returns a nil error.
func (t *PipelineTransport) Close() error {
	t.m.Lock()
	defer t.m.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.cancelCtx(ErrClosedTransport)
	for conn := range t.conns {
		conn.closeWithErr(ErrClosedTransport, true)
		delete(t.conns, conn)
	}
	for conn := range t.eols {
		conn.closeWithErr(ErrClosedTransport, true)
		delete(t.conns, conn)
	}
	return nil
}

type dialingCall struct {
	done chan struct{}
	c    *pipelineConn
	err  error

	m        sync.Mutex
	reserved int
}

func (call *dialingCall) reserve(max int) bool {
	call.m.Lock()
	defer call.m.Unlock()
	if call.reserved >= max {
		return false
	}
	call.reserved++
	return true
}

func (call *dialingCall) release() {
	call.m.Lock()
	defer call.m.Unlock()
	call.reserved--
}

func (t *PipelineTransport) dial(call *dialingCall) {
	ctx, cancel := context.WithTimeout(t.ctx, t.dialTimeout)
	c, err := t.dialFunc(ctx)
	cancel()

	var pc *pipelineConn
	if c != nil {
		pc = newPipelineConn(c, t)
	}

	t.m.Lock()
	delete(t.dialingCalls, call)
	if t.closed {
		t.m.Unlock()
		if c != nil {
			c.Close()
		}
		call.err = ErrClosedTransport
		close(call.done)
		return
	}
	if pc != nil {
		t.conns[pc] = struct{}{}
	}
	t.m.Unlock()
	call.c = pc
	call.err = err
	close(call.done)

	if pc != nil { // pc is in the transport, run its io loops
		pc.startLoops()
		debugLogTransportNewConn(pc.c, t.logger)
	}
	if err != nil {
		t.logger.Check(zap.WarnLevel, "failed to dial pipeline conn").Write(zap.Error(err))
	}
}
