package router

import (
	"encoding/binary"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func findECS(m *dnsmsg.Msg) netip.Prefix {
	for _, r := range m.Additionals {
		if rr, ok := r.(*dnsmsg.RawResource); ok {
			if rr.Type == dnsmsg.TypeOPT {
				b := rr.Data
				for len(b) >= 4 {
					opCode := binary.BigEndian.Uint16(b[:2])
					l := int(binary.BigEndian.Uint16(b[2:4]))
					b = b[4:]

					if len(b) < l {
						return netip.Prefix{}
					}
					if opCode == 8 {
						return unpackECS(b[:l])
					}
					b = b[l:]
				}
			}
		}
	}
	return netip.Prefix{}
}

func unpackECS(b []byte) netip.Prefix {
	if len(b) < 4 {
		return netip.Prefix{}
	}
	family := binary.BigEndian.Uint16(b[:2])
	mask := b[2]
	switch family {
	case 1:
		var a [4]byte
		copy(a[:], b[4:])
		return netip.PrefixFrom(netip.AddrFrom4(a), int(mask))
	case 2:
		var a [16]byte
		copy(a[:], b[4:])
		return netip.PrefixFrom(netip.AddrFrom16(a), int(mask))
	default:
		return netip.Prefix{}
	}
}

// For convenient, if addr is invalid, it returns nil.
func makeEdns0ClientSubnetReqOpt(addr netip.Addr) pool.Buffer {
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
		b      pool.Buffer
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
		copy(b[8:], ip[:])
	case addr.Is6():
		length = length6
		family = family6
		mask = mask6
		addr = maskAddr(addr, mask)
		ip := addr.As16()
		b = pool.GetBuf(4 + length6)
		copy(b[8:], ip[:])
	default:
		return nil
	}

	bb := b

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
