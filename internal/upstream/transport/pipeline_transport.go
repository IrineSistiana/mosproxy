package transport

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/upstream/transport/connpool"
	"github.com/rs/zerolog"
)

const (
	defaultPipelineMaxConcurrent = 64
)

var _ Transport = (*PipelineTransport)(nil)

// PipelineTransport will pipeline queries as RFC 7766 6.2.1.1 suggested.
// It also can reuse udp socket. Since dns over udp is some kind of "pipeline".
type PipelineTransport struct {
	opts PipelineOpts

	logger *zerolog.Logger // not nil

	pool *connpool.Pool
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

	Logger *zerolog.Logger
}

func NewPipelineTransport(opts PipelineOpts) *PipelineTransport {
	t := &PipelineTransport{
		opts:   opts,
		logger: nonNilLogger(opts.Logger),
	}
	t.pool = connpool.NewPool(connpool.Opts{
		Dial: func(ctx context.Context) (connpool.PoolConn, error) {
			ctx, cancel := context.WithTimeout(ctx, t.dialTimeout())
			defer cancel()
			c, err := opts.DialContext(ctx)
			if err != nil {
				return nil, err
			}
			return newPipelineConn(c, t), nil
		},
		MaxDialingConnReq: uint64(t.maxConcurrentQuery()),
	})
	return t
}

func (t *PipelineTransport) dialTimeout() time.Duration {
	return defaultIfLeZero(t.opts.DialTimeout, defaultDialTimeout)
}

func (t *PipelineTransport) maxConcurrentQuery() int {
	return defaultIfLeZero(t.opts.MaxConcurrentQuery, defaultPipelineMaxConcurrent)
}

func (t *PipelineTransport) connIdleTimeout() time.Duration {
	return defaultIfLeZero(t.opts.IdleTimeout, defaultIdleTimeout)
}

func (t *PipelineTransport) ExchangeContext(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	if len(m) < dnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}

	retry := 0
	errs := make([]error, 0)
	for {
		conn, newConn, err := t.getConn()
		if err != nil {
			errs = append(errs, err)
			return nil, joinErr(errs)
		}

		resp, err := conn.exchange(ctx, m)
		if err != nil {
			errs = append(errs, err)
			if !newConn && retry < 5 && !ctxIsDone(ctx) {
				retry++
				continue
			}
			return nil, joinErr(errs)
		}
		return resp, nil
	}
}

func setQid(payload []byte, off int, qid uint16) {
	binary.BigEndian.PutUint16(payload[off:], qid)
}

func (t *PipelineTransport) getConn() (_ *pipelineConn, newConn bool, err error) {
	c, newConn, err := t.pool.GetConn()
	if err != nil {
		return nil, false, err
	}
	return c.(*pipelineConn), newConn, nil
}

// Close closes PipelineTransport and all its connections.
// It always returns a nil error.
func (t *PipelineTransport) Close() error {
	return t.pool.Close()
}
