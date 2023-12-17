package transport

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

var (
	ErrClosedTransport = errors.New("transport has been closed")
	ErrPayloadTooSmall = errors.New("payload is too small")
	ErrPayloadOverFlow = errors.New("payload is too large")
	ErrIdleTimeOut     = errors.New("idle timeout")
)

const (
	defaultIdleTimeout = time.Second * 10
	defaultDialTimeout = time.Second * 5
)

type Transport interface {
	// ExchangeContext exchanges query message m to the upstream, and returns
	// response. It MUST NOT keep or modify m.
	// It is the caller's responsibility to release the resp.
	ExchangeContext(ctx context.Context, m []byte) (resp *dnsmsg.Msg, err error)

	io.Closer
}
