package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	// RFC 9250 4.3. DoQ Error Codes
	_DOQ_NO_ERROR          = quic.StreamErrorCode(0x0)
	_DOQ_INTERNAL_ERROR    = quic.StreamErrorCode(0x1)
	_DOQ_REQUEST_CANCELLED = quic.StreamErrorCode(0x3)
)

var _ Transport = (*QuicTransport)(nil)

type QuicTransport struct {
	ctx         context.Context
	cancelCtx   context.CancelCauseFunc
	dial        func(ctx context.Context) (quic.Connection, error)
	dialTimeout time.Duration
	logger      *zap.Logger

	m           sync.Mutex
	closed      bool
	dialingCall *dialingQuicCall
	c           quic.Connection
}

type QuicTransportOpts struct {
	// DialContext specifies the method to dial a connection to the server.
	// DialContext MUST NOT be nil.
	DialContext func(ctx context.Context) (quic.Connection, error)

	// DialTimeout specifies the timeout for DialFunc.
	// Default is defaultDialTimeout.
	DialTimeout time.Duration
	Logger      *zap.Logger
}

func NewQuicTransport(opt QuicTransportOpts) *QuicTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &QuicTransport{
		ctx:       ctx,
		cancelCtx: cancel,
	}
	t.dial = opt.DialContext
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, defaultDialTimeout)
	setNonNilLogger(&t.logger, opt.Logger)
	return t
}

func (t *QuicTransport) Close() error {
	t.m.Lock()
	defer t.m.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true
	t.cancelCtx(ErrClosedTransport)
	if t.c != nil {
		t.c.CloseWithError(quic.ApplicationErrorCode(_DOQ_NO_ERROR), "")
	}
	return nil
}

func (t *QuicTransport) ExchangeContext(ctx context.Context, q []byte) (*dnsmsg.Msg, error) {
	if len(q) < 12 {
		return nil, ErrPayloadTooSmall
	}
	payload, err := copyMsgWithLenHdr(q)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(payload)

	// 4.2.1.  DNS Message IDs
	//    When sending queries over a QUIC connection, the DNS Message ID MUST
	//    be set to 0.  The stream mapping for DoQ allows for unambiguous
	//    correlation of queries and responses, so the Message ID field is not
	//    required.
	orgQid := binary.BigEndian.Uint16(payload.B()[2:])
	binary.BigEndian.PutUint16(payload.B()[2:], 0)

	resp, err := t.exchangePayload(ctx, payload.B())
	if err != nil {
		return nil, err
	}
	resp.Header.ID = orgQid
	return resp, nil
}

func (t *QuicTransport) exchangePayload(ctx context.Context, payload []byte) (*dnsmsg.Msg, error) {
	start := time.Now()
	retry := 0
	for {
		c, call, closed := t.getConn()
		if closed {
			return nil, ErrClosedTransport
		}
		if c != nil {
			b, err := t.exchangeConn(ctx, payload, c)
			if err != nil {
				if retry < 3 && time.Since(start) < time.Second && !ctxIsDone(ctx) {
					retry++
					continue
				}
			}
			return b, err
		}
		return t.exchangeDialingCall(ctx, payload, call)
	}

}

type ErrNoAvailableQuicConn struct {
	cause error
}

func (e *ErrNoAvailableQuicConn) Error() string {
	return fmt.Sprintf("failed to get available quic conn, %s", e.cause)
}

func (e *ErrNoAvailableQuicConn) Unwrap() error {
	return e.cause
}

func (t *QuicTransport) exchangeDialingCall(ctx context.Context, payload []byte, call *dialingQuicCall) (*dnsmsg.Msg, error) {
	select {
	case <-ctx.Done():
		return nil, &ErrNoAvailableQuicConn{cause: context.Cause(ctx)}
	case <-call.done:
		c, err := call.c, call.err
		if err != nil {
			return nil, &ErrNoAvailableQuicConn{cause: err}
		}
		return t.exchangeConn(ctx, payload, c)
	}
}

func (t *QuicTransport) exchangeConn(ctx context.Context, payload []byte, c quic.Connection) (*dnsmsg.Msg, error) {
	s, err := c.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream, %w", err)
	}
	return t.exchangeStream(ctx, payload, s)
}

func (t *QuicTransport) exchangeStream(ctx context.Context, payload []byte, stream quic.Stream) (resp *dnsmsg.Msg, err error) {
	type res struct {
		resp *dnsmsg.Msg
		err  error
	}
	rc := make(chan res, 1)
	pool.Go(func() {
		_, err = stream.Write(payload)
		if err != nil {
			stream.CancelRead(_DOQ_REQUEST_CANCELLED)
			stream.CancelWrite(_DOQ_REQUEST_CANCELLED)
			rc <- res{resp: nil, err: err}
			return
		}

		// RFC 9250 4.2
		//    The client MUST send the DNS query over the selected stream and MUST
		//    indicate through the STREAM FIN mechanism that no further data will
		//    be sent on that stream.
		//
		// Call Close() here will send the STREAM FIN. It won't close Read.
		stream.Close()
		r, _, err := dnsutils.ReadMsgFromTCP(stream)
		stream.CancelRead(_DOQ_REQUEST_CANCELLED)
		rc <- res{resp: r, err: err}
	})

	select {
	case <-ctx.Done():
		// Note: According to docs of quic-go, "Close MUST NOT
		// be called after CancelWrite".
		// However, it will just return an error. So, we are safe here.
		stream.CancelRead(_DOQ_REQUEST_CANCELLED)
		stream.CancelWrite(_DOQ_REQUEST_CANCELLED)
		return nil, context.Cause(ctx)
	case r := <-rc:
		resp := r.resp
		err := r.err
		return resp, err
	}
}

func (t *QuicTransport) getConn() (_ quic.Connection, _ *dialingQuicCall, closed bool) {
	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		return nil, nil, true
	}

	if t.c != nil {
		t.m.Unlock()
		return t.c, nil, false
	}
	if t.dialingCall != nil {
		t.m.Unlock()
		return nil, t.dialingCall, false
	}

	call := &dialingQuicCall{
		done: make(chan struct{}),
	}
	t.dialingCall = call
	t.m.Unlock()
	go t.runDialingCall(call)
	return nil, call, false
}

func (t *QuicTransport) runDialingCall(call *dialingQuicCall) {
	ctx, cancel := context.WithTimeout(t.ctx, t.dialTimeout)
	c, err := t.dial(ctx)
	cancel()

	t.m.Lock()
	t.dialingCall = nil
	if t.closed {
		t.m.Unlock()
		if c != nil {
			c.CloseWithError(quic.ApplicationErrorCode(_DOQ_NO_ERROR), "")
		}
		return
	}
	t.c = c
	t.m.Unlock()

	if err != nil {
		t.logger.Check(zap.WarnLevel, "failed to dial quic conn").Write(zap.Error(err))
	}
	if c != nil {
		debugLogTransportNewConn(c, t.logger)
	}
	call.c, call.err = c, err
	close(call.done)

	if c != nil {
		connCtx := c.Context()
		select {
		case <-t.ctx.Done():
		case <-connCtx.Done():
			t.m.Lock()
			t.c = nil
			t.m.Unlock()
			c.CloseWithError(quic.ApplicationErrorCode(_DOQ_NO_ERROR), "")
			cause := context.Cause(connCtx)
			debugLogTransportConnClosed(c, t.logger, cause)
		}
	}
}

type dialingQuicCall struct {
	done chan struct{}
	c    quic.Connection
	err  error
}
