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
	"github.com/rs/zerolog"
)

const (
	// RFC 9250 4.3. DoQ Error Codes
	_DOQ_NO_ERROR          = quic.StreamErrorCode(0x0)
	_DOQ_INTERNAL_ERROR    = quic.StreamErrorCode(0x1)
	_DOQ_REQUEST_CANCELLED = quic.StreamErrorCode(0x3)
)

var _ Transport = (*QuicTransport)(nil)

type QuicTransport struct {
	opts      QuicTransportOpts
	ctx       context.Context
	cancelCtx context.CancelCauseFunc
	logger    *zerolog.Logger

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
	Logger      *zerolog.Logger
}

func NewQuicTransport(opts QuicTransportOpts) *QuicTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &QuicTransport{
		opts:      opts,
		ctx:       ctx,
		cancelCtx: cancel,
		logger:    nonNilLogger(opts.Logger),
	}
	return t
}

func (t *QuicTransport) dialTimeout() time.Duration {
	return defaultIfLeZero(t.opts.DialTimeout, defaultDialTimeout)
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
	orgQid := binary.BigEndian.Uint16(payload[2:])
	binary.BigEndian.PutUint16(payload[2:], 0)

	resp, err := t.exchangePayload(ctx, payload)
	if err != nil {
		return nil, err
	}
	resp.Header.ID = orgQid
	return resp, nil
}

func (t *QuicTransport) exchangePayload(ctx context.Context, payload []byte) (*dnsmsg.Msg, error) {
	retry := 0
	for {
		c, newConn, err := t.getConn(ctx)
		if err != nil {
			return nil, err
		}

		b, err := t.exchangeConn(ctx, payload, c)
		if err != nil {
			if !newConn && retry < 5 && !ctxIsDone(ctx) {
				retry++
				continue
			}
		}
		return b, err
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
	go func() {
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
	}()

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

func (t *QuicTransport) getConn(ctx context.Context) (_ quic.Connection, newConn bool, _ error) {
	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		return nil, false, ErrClosedTransport
	}

	if t.c != nil {
		if !ctxIsDone(t.c.Context()) {
			t.m.Unlock()
			return t.c, false, nil
		}
		// dead conn
		t.c = nil
	}
	if dc := t.dialingCall; dc != nil {
		t.m.Unlock()
		c, err := dc.wait(ctx)
		return c, true, err
	}

	dc := &dialingQuicCall{
		done: make(chan struct{}),
	}
	t.dialingCall = dc
	t.m.Unlock()
	go t.runDialingCall(dc)
	c, err := dc.wait(ctx)
	return c, true, err
}

func (t *QuicTransport) runDialingCall(call *dialingQuicCall) {
	ctx, cancel := context.WithTimeout(t.ctx, t.dialTimeout())
	c, err := t.opts.DialContext(ctx)
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

	call.c, call.err = c, err
	close(call.done)

	if err != nil {
		t.logger.Warn().
			Err(err).
			Msg("failed to dial conn")
	}
	if c != nil {
		debugLogTransportConnOpen(c, t.logger)
	}

}

type dialingQuicCall struct {
	done chan struct{}
	c    quic.Connection
	err  error
}

func (call *dialingQuicCall) wait(ctx context.Context) (quic.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-call.done:
		return call.c, call.err
	}
}
