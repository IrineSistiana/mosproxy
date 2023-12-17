package router

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap/zapcore"
)

type Response struct {
	Msg     *dnsmsg.Msg
	RuleIdx int
	Cached  bool
}

type RequestContext struct {
	RemoteAddr netip.AddrPort // client addr, maybe invalid
	LocalAddr  netip.AddrPort // inbound/server addr, maybe invalid

	Response Response

	start time.Time
	uid   uint32 // only for logging
}

var requestContextUid atomic.Uint32

var requestContextPool sync.Pool = sync.Pool{New: func() any { return new(RequestContext) }}

func getRequestContext() *RequestContext {
	rc := requestContextPool.Get().(*RequestContext)
	rc.start = time.Now()
	rc.uid = requestContextUid.Add(1)
	return rc
}

func releaseRequestContext(rc *RequestContext) {
	*rc = RequestContext{}
	requestContextPool.Put(rc)
}

func (rc *RequestContext) MarshalLogObject(e zapcore.ObjectEncoder) error {
	printAddr := func(e zapcore.ObjectEncoder, addr netip.AddrPort, key string) {
		buf := pool.GetBuf(39 + 2 + 6) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
		defer pool.ReleaseBuf(buf)
		b := addr.AppendTo(buf.B()[:0])
		e.AddByteString(key, b)
	}
	if rc.RemoteAddr.IsValid() {
		printAddr(e, rc.RemoteAddr, "remote")
	}
	if rc.LocalAddr.IsValid() {
		printAddr(e, rc.LocalAddr, "local")
	}

	resp := rc.Response.Msg
	if rc.Response.Msg != nil {
		e.AddInt("rule", rc.Response.RuleIdx)
		e.AddUint16("rcode", uint16(resp.Header.RCode))
		if rc.Response.Cached {
			e.AddBool("cached", true)
		}
	}

	if !rc.start.IsZero() {
		e.AddDuration("elapsed", time.Since(rc.start))
	}
	return nil
}
