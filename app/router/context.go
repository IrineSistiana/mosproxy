package router

import (
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap/zapcore"
)

type request struct {
	q      *dnsmsg.Question // not nil, always has lower case domain name
	remote netip.AddrPort   // client addr, maybe invalid
	local  netip.AddrPort   // inbound/server addr, maybe invalid
}

type response struct {
	m        *dnsmsg.Msg
	ruleIdx  int
	upstream string
	cached   bool
}

type reqContext struct {
	start time.Time
	req   request
	resp  response
}

func (rc *reqContext) MarshalLogObject(e zapcore.ObjectEncoder) error {
	printAddr := func(e zapcore.ObjectEncoder, addr netip.AddrPort, key string) {
		buf := pool.GetBuf(39 + 2 + 6) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
		defer pool.ReleaseBuf(buf)
		b := addr.AppendTo(buf.B()[:0])
		e.AddByteString(key, b)
	}

	q := rc.req.q
	e.AddByteString("qname", q.Name.B())
	e.AddUint16("qclass", uint16(q.Class))
	e.AddUint16("qtype", uint16(q.Type))
	if rc.req.remote.IsValid() {
		printAddr(e, rc.req.remote, "remote")
	}
	if rc.req.local.IsValid() {
		printAddr(e, rc.req.local, "local")
	}

	r := rc.resp.m
	if r != nil {
		e.AddUint16("rcode", uint16(r.Header.RCode))
		if len(rc.resp.upstream) > 0 {
			e.AddString("upstream", rc.resp.upstream)
		}
		if rc.resp.cached {
			e.AddBool("cached", true)
		}
	}
	e.AddInt("rule", rc.resp.ruleIdx)
	e.AddDuration("elapsed", time.Since(rc.start))
	return nil
}
