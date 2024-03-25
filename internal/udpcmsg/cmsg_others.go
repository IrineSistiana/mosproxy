//go:build !linux

package udpcmsg

import (
	"net"
	"net/netip"
)

func Ok() bool {
	return false
}

func SetOpt(c *net.UDPConn) (inet6 bool, err error) {
	panic("not impl")
}

func ParseLocalAddr(oob []byte) (netip.Addr, error) {
	panic("not impl")
}

func CmsgSize(addr netip.Addr) int {
	panic("not impl")
}

func CmsgPktInfo(b []byte, addr netip.Addr) []byte {
	panic("not impl")
}
