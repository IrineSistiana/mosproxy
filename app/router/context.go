package router

import (
	"net/netip"
)

type RespMeta struct {
	RuleIdx int
	Cached  bool
	IpMark  string
}

type QueryMeta struct {
	RemoteAddr netip.AddrPort // client addr, maybe invalid
	LocalAddr  netip.AddrPort // inbound/server addr, maybe invalid
}
