package router

import (
	"context"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
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

func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
