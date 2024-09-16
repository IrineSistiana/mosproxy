package router

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
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
	// static info. Do not change.

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

	// dynamic info. Can be changed by middleware.

	ECS2Upstream netip.Prefix // ECS that is going to send to upstream.
	ECSZone      string       // zone name for the ECS addr.

	// Set be the Handler.
	Resp  *dnsmsg.Msg // Handler MUST set Resp upon returning.
	Trace Trace
}

type Trace struct {
	Cached      bool   // Resp is from cache.
	RuleIdx     int    // Matched rule id.
	UpstreamTag string // Resp is from this upstream.
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
