package transport

import (
	"context"
	"encoding/binary"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap"
	"golang.org/x/exp/constraints"
)

const (
	dnsHeaderLen = 12 // minimum dns msg size
)

func copyMsgWithLenHdr(m []byte) (*pool.Buffer, error) {
	l := len(m)
	if l > 65535 {
		return nil, ErrPayloadOverFlow
	}
	b := pool.GetBuf(l + 2)
	binary.BigEndian.PutUint16(b.B(), uint16(l))
	copy(b.B()[2:], m)
	return b, nil
}

func copyMsg(m []byte) *pool.Buffer {
	b := pool.GetBuf(len(m))
	copy(b.B(), m)
	return b
}

func setDefaultGZ[T constraints.Float | constraints.Integer](i *T, s, d T) {
	if s > 0 {
		*i = s
	} else {
		*i = d
	}
}

var nopLogger = zap.NewNop()

func setNonNilLogger(i **zap.Logger, s *zap.Logger) {
	if s != nil {
		*i = s
	} else {
		*i = nopLogger
	}
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
