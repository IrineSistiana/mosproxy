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

		truncated4 = 3
		truncated6 = 7

		length4 = 2 + 1 + 1 + truncated4 // FAMILY + SOURCE PREFIX-LENGTH + SCOPE PREFIX-LENGTH + Addr
		length6 = 2 + 1 + 1 + truncated6

		family4 = 1
		family6 = 2
	)
	maskAddr := func(addr netip.Addr, mask uint8) netip.Addr {
		p, _ := addr.Prefix(int(mask))
		return p.Addr()
	}

	var (
		b      *pool.Buffer
		length uint16
		family uint16
		mask   uint8
	)
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		length = length4
		family = family4
		mask = mask4
		addr = maskAddr(addr, mask)
		ip := addr.As4()
		b = pool.GetBuf(4 + length4)
		copy(b.B()[8:], ip[:])
	case addr.Is6():
		length = length6
		family = family6
		mask = mask6
		addr = maskAddr(addr, mask)
		ip := addr.As16()
		b = pool.GetBuf(4 + length6)
		copy(b.B()[8:], ip[:])
	default:
		return nil
	}

	bb := b.B()

	// https://tools.ietf.org/html/rfc7871
	// OPTION-CODE, 2 octets, for ECS is 8 (0x00 0x08).
	binary.BigEndian.PutUint16(bb[0:2], 8)      // subnetCode, always 8
	binary.BigEndian.PutUint16(bb[2:4], length) // length
	// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1, ipv6 = 2
	binary.BigEndian.PutUint16(bb[4:6], family)
	// SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS to be used for the lookup.
	// In responses, it mirrors the same value as in the queries.
	bb[6] = mask

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	bb[7] = 0
	return b
}
