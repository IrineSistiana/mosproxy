package router

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/rs/zerolog"
)

type Proto uint8

const (
	ProtoUnKnown Proto = 0
	ProtoUDP     Proto = 1
	ProtoTCP     Proto = 2
	ProtoTLS     Proto = 3
	ProtoHTTP    Proto = 4
	ProtoHTTPS   Proto = 5
	ProtoQUIC    Proto = 6
)

type QueryCtx struct {
	Qid   uint32 // rand id for logging only. Not the dns msg id.
	Start time.Time

	// DNS query
	Question  dnsmsg.Question // Always valid.
	ClientECS netip.Prefix    // ECS from client query. Maybe invalid.

	// Server side info
	ServerTag  string         // Which server the query comes from. Maybe empty if not set.
	Protocol   Proto          // Server protocol
	RemoteAddr netip.AddrPort // Client addr, maybe invalid. e.g from unix socket
	ServerName []byte         // TLS servername, if protocol is based on TLS (DoT,DoH,DoQ)
	Host       []byte         // HTTP host (if protocol is based on HTTP)
	Path       []byte         // HTTP path (if protocol is based on HTTP)

	// Other info
	ECS2Upstream netip.Prefix // ECS that is going to send to upstream.
	ECSZone      string       // zone name for the ECS addr.
	Prefetch     bool         // This is a prefetch query.

	// Resp
	Resp  *dnsmsg.Msg
	Trace Trace
}

type Trace struct {
	RuleIdx  int    // Matched rule id.
	Cached   bool   // Resp is from cache.
	Upstream string // Resp is from this upstream.
}

var queryCtxPool = sync.Pool{}

func NewQueryCtx() *QueryCtx {
	q, ok := queryCtxPool.Get().(*QueryCtx)
	if !ok {
		q = &QueryCtx{}
	}
	q.Qid = rand.Uint32()
	q.Start = time.Now()
	return q
}

func (q *QueryCtx) Reset() {
	q.Qid = 0
	q.Start = time.Time{}
	q.Question.Reset()
	q.ClientECS = netip.Prefix{}
	q.Protocol = ProtoUnKnown
	q.RemoteAddr = netip.AddrPort{}
	zero(&q.ServerName)
	zero(&q.Host)
	zero(&q.Path)

	q.ECS2Upstream = netip.Prefix{}
	q.ECSZone = ""
	q.Prefetch = false

	if q.Resp != nil {
		dnsmsg.ReleaseMsg(q.Resp)
		q.Resp = nil
	}
	q.Trace.Reset()
}

func (q *QueryCtx) Copy() *QueryCtx {
	n := NewQueryCtx()
	n.Qid = q.Qid
	n.Start = q.Start
	n.Question.CopyFrom(&q.Question)
	n.ClientECS = q.ClientECS
	n.Protocol = q.Protocol
	n.ServerName = append(n.ServerName, q.ServerName...)
	n.Host = append(n.Host, q.Host...)
	n.Path = append(n.Path, q.Path...)

	n.ECS2Upstream = q.ECS2Upstream
	n.ECSZone = q.ECSZone
	n.Prefetch = q.Prefetch

	if q.Resp != nil {
		n.Resp = q.Resp.Copy()
	}
	q.Trace.CopyTo(&n.Trace)
	return n
}

func (t *Trace) Reset() {
	*t = Trace{}
}

func (t *Trace) CopyTo(n *Trace) {
	*n = *t
}

func zero[T any](s *[]T) {
	clear(*s)
	*s = (*s)[:0]
}

func ReleaseQueryCtx(q *QueryCtx) {
	q.Reset()
	queryCtxPool.Put(q)
}

// Important info about the query, qname, type, ecs zone, etc...
func (q *QueryCtx) LogQuery() *zerolog.Event {
	e := zerolog.Dict()
	e.Uint32("qid", q.Qid)

	b := pool.GetBuf(1024)
	e.Bytes("name", q.Question.Name.AppendReadableTo(b[:0]))
	pool.ReleaseBuf(b)
	e.Uint16("class", uint16(q.Question.Class))
	e.Uint16("type", uint16(q.Question.Type))
	logNetipPrefix(e, "ecs", q.ECS2Upstream)
	if len(q.ECSZone) > 0 {
		e.Str("ecs_zone", q.ECSZone)
	}
	if q.Prefetch {
		e.Bool("prefetch", true)
	}
	return e
}

func (q *QueryCtx) LogServerMeta() *zerolog.Event {
	e := zerolog.Dict()
	if len(q.ServerTag) > 0 {
		e.Str("server", q.ServerTag)
	}
	logNetipAddrPort(e, "remote", q.RemoteAddr)
	if len(q.ServerName) > 0 {
		e.Bytes("sni", q.ServerName)
	}
	if len(q.Host) > 0 {
		e.Bytes("host", q.Host)
	}
	if len(q.Path) > 0 {
		e.Bytes("path", q.Path)
	}
	return e
}

func (q *QueryCtx) LogResp() *zerolog.Event {
	e := zerolog.Dict()
	if r := q.Resp; r != nil {
		e.Uint16("rcode", uint16(r.RCode))
	}

	e.Int("rule", q.Trace.RuleIdx)
	if q.Trace.Cached {
		e.Bool("cached", true)
	}
	if len(q.Trace.Upstream) > 0 {
		e.Str("upstream", q.Trace.Upstream)
	}

	if !q.Start.IsZero() {
		e.Dur("elapsed", time.Since(q.Start))
	}
	return e
}

// If addr is invalid, do nothing.
func logNetipAddrPort(e *zerolog.Event, key string, addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 6 ":xxxxx" port.
	defer pool.ReleaseBuf(buf)
	e.Bytes(key, addr.AppendTo(buf[:0]))
}

// If p is invalid, do nothing.
func logNetipPrefix(e *zerolog.Event, key string, p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	buf := pool.GetBuf(64) // ipv6: maximum 39 bytes string + 2 for "[]" + 4 "/xxx" bits.
	defer pool.ReleaseBuf(buf)
	e.Bytes(key, p.AppendTo(buf[:0]))
}
