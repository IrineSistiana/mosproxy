package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
	"golang.org/x/exp/constraints"
)

const (
	dnsHeaderLen = 12 // minimum dns msg size
)

func copyMsgWithLenHdr(m []byte) (pool.Buffer, error) {
	l := len(m)
	if l > 65535 {
		return nil, ErrPayloadOverFlow
	}
	b := pool.GetBuf(l + 2)
	binary.BigEndian.PutUint16(b, uint16(l))
	copy(b[2:], m)
	return b, nil
}

func copyMsg(m []byte) pool.Buffer {
	b := pool.GetBuf(len(m))
	copy(b, m)
	return b
}

func defaultIfLeZero[T constraints.Float | constraints.Integer](i, d T) T {
	if i > 0 {
		return i
	}
	return d
}

func nonNilLogger(l *zerolog.Logger) *zerolog.Logger {
	if l == nil {
		l = mlog.Nop()
	}
	return l
}

func ctxIsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func bytesToStringUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// If errs is empty, returns nil.
// If errs contains only one error, returns that err.
// Else, calls errors.Join(errs...).
func joinErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errors.Join(errs...)
}
