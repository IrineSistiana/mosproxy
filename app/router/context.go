package router

import (
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// Query meta data from server side.
type QueryMeta struct {
	RemoteAddr netip.AddrPort // client addr, maybe invalid
	LocalAddr  netip.AddrPort // inbound/server addr, maybe invalid
}

// Query info.
type QueryInfo struct {
	Id     uint16
	OpCode dnsmsg.OpCode
	Rd     bool         // RecursionDesired
	EDNS0  bool         // Has EDNS0 section
	ECS    netip.Prefix // EDNS0 Client subnet
}

type qCtx struct {
	q     *dnsmsg.Question
	qMeta QueryMeta
	qInfo QueryInfo
}

type RespMeta struct {
	RuleIdx int
	Cached  bool
	IpMark  string
}
