package router

import (
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func addOrReplaceOpt(m *dnsmsg.Msg, udpSize uint16) {
	removeOpt(m)
	m.Additionals.Add(edns0Opt(udpSize))
}

func edns0Opt(udpSize uint16) *dnsmsg.Resource {
	if udpSize < 512 {
		udpSize = 512
	}
	opt := dnsmsg.GetRR()
	opt.Name = pool.GetBuf(1)
	opt.Name.B()[0] = '.'
	opt.Class = dnsmsg.Class(udpSize)
	opt.Type = dnsmsg.TypeOPT
	return opt
}

// remove edns0 rr from m.
func removeOpt(m *dnsmsg.Msg) {
	for n := m.Additionals.Tail(); n != nil; n = n.Prev() {
		r := n.Value()
		if r.Type == dnsmsg.TypeOPT {
			m.Additionals.Remove(n)
			dnsmsg.ReleaseRR(r)
			return
		}
	}
}

func str2BytesUnsafe(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func asciiToLower(s []byte) {
	for i, c := range s {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
			s[i] = c
		}
	}
}

func copyBuf(b []byte) *pool.Buffer {
	c := pool.GetBuf(len(b))
	copy(c.B(), b)
	return c
}
