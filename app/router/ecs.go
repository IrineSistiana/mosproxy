package router

import (
	"encoding/binary"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

// For convenient, if addr is invalid, it returns nil.
func makeEdns0ClientSubnetReqOpt(addr netip.Addr) *pool.Buffer {
	const (
		// Recommended by rfc7871 11.1
		mask4 = 24
		mask6 = 56 // and rfc6177.
		// TODO: Make edns0 subnet masks configurable?
	)
	maskAddr := func(addr netip.Addr, mask int) netip.Addr {
		p, _ := addr.Prefix(mask)
		return p.Addr()
	}

	var (
		b      *pool.Buffer
		l      uint16
		family uint16
		mask   uint8
	)
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		l = 8
		family = 1
		mask = uint8(mask4)
		addr = maskAddr(addr, mask4)
		ip := addr.As4()
		b = pool.GetBuf(12) // 8+4
		copy(b.B()[8:], ip[:])
	case addr.Is6():
		l = 20
		family = 2
		mask = uint8(mask6)
		addr = maskAddr(addr, mask6)
		ip := addr.As16()
		b = pool.GetBuf(24) // 8+16
		copy(b.B()[8:], ip[:])
	default:
		return nil
	}

	// https://tools.ietf.org/html/rfc7871
	// OPTION-CODE, 2 octets, for ECS is 8 (0x00 0x08).
	binary.BigEndian.PutUint16(b.B()[0:2], 8) // subnetCode, always 8
	binary.BigEndian.PutUint16(b.B()[2:4], l) // length
	// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1, ipv6 = 2
	binary.BigEndian.PutUint16(b.B()[4:6], family)
	// SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS to be used for the lookup.
	// In responses, it mirrors the same value as in the queries.
	b.B()[6] = mask

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	b.B()[7] = 0
	return b
}
