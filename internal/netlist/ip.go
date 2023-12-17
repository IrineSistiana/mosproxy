package netlist

import (
	"encoding/binary"
	"net/netip"
)

type Ipv6 struct {
	h uint64
	l uint64
}

// b must at least has length of 16.
func (ip Ipv6) Put(b []byte) {
	binary.BigEndian.PutUint64(b, ip.h)
	binary.BigEndian.PutUint64(b[8:], ip.l)
}

func (ip Ipv6) cmp(ip2 Ipv6) int {
	if ip.h < ip2.h {
		return -1
	}
	if ip.h > ip2.h {
		return 1
	}

	if ip.l < ip2.l {
		return -1
	}
	if ip.l > ip2.l {
		return 1
	}
	return 0
}

func (ip Ipv6) ToAddr() netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], ip.h)
	binary.BigEndian.PutUint64(b[8:], ip.l)
	return netip.AddrFrom16(b)
}

func (ip Ipv6) String() string {
	return ip.ToAddr().String()
}

func addr2Ipv6(addr netip.Addr) Ipv6 {
	b := addr.As16()
	return Ipv6{
		h: binary.BigEndian.Uint64(b[:8]),
		l: binary.BigEndian.Uint64(b[8:]),
	}
}
