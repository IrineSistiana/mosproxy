package router

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

type Response struct {
	Msg     *dnsmsg.Msg
	RuleIdx int
	Cached  bool
	IpMark  string
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

// Note: Response will be released as well if not nil.
func releaseRequestContext(rc *RequestContext) {
	if rc.Response.Msg != nil {
		dnsmsg.ReleaseMsg(rc.Response.Msg)
	}
	*rc = RequestContext{}
	requestContextPool.Put(rc)
}

func (rc *RequestContext) MarshalZerologObject(e *zerolog.Event) {
	printAddr := func(e *zerolog.Event, addr netip.AddrPort, key string) {
		buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
		defer pool.ReleaseBuf(buf)
		b := addr.AppendTo(buf[:0])
		e.Bytes(key, b)
	}
	if rc.RemoteAddr.IsValid() {
		printAddr(e, rc.RemoteAddr, "remote")
	}
	if rc.LocalAddr.IsValid() {
		printAddr(e, rc.LocalAddr, "local")
	}

	e.Int("rule", rc.Response.RuleIdx)

	resp := rc.Response.Msg
	if rc.Response.Msg != nil {
		e.Uint16("rcode", uint16(resp.Header.RCode))
	}
	if rc.Response.Cached {
		e.Bool("cached", true)
	}

	if len(rc.Response.IpMark) > 0 {
		e.Str("ip_mark", rc.Response.IpMark)
	}

	if !rc.start.IsZero() {
		e.Dur("elapsed", time.Since(rc.start))
	}
	e.Uint32("qid", rc.uid)
}
