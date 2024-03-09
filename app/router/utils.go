package router

import (
	"context"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func addOrReplaceOpt(m *dnsmsg.Msg, udpSize uint16) {
	rr := dnsmsg.PopEDNS0(m)
	if rr != nil {
		dnsmsg.ReleaseResource(rr)
	}
	m.Additionals = append(m.Additionals, newEDNS0(udpSize))
}

func newEDNS0(udpSize uint16) *dnsmsg.RawResource {
	if udpSize < 512 {
		udpSize = 512
	}
	opt := dnsmsg.NewRaw()
	// opt.Name is zero, which equals "."
	opt.Class = dnsmsg.Class(udpSize)
	opt.Type = dnsmsg.TypeOPT
	return opt
}

func str2BytesUnsafe(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func copyBuf(b []byte) pool.Buffer {
	c := pool.GetBuf(len(b))
	copy(c, b)
	return c
}

func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
