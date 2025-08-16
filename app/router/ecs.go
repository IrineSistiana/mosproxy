package router

import (
	"encoding/binary"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
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

// For convenient, if p is invalid, it returns nil.
func makeEdns0ClientSubnetReqOpt(p netip.Prefix) pool.Buffer {
	const (
		family4 = 1
		family6 = 2
	)

	if !p.IsValid() {
		return nil
	}

	// make sure addr is masked and unmapped.
	if p.Addr().Is4In6() {
		p, _ = p.Addr().Unmap().Prefix(p.Bits() - 96)
	}
	p = p.Masked()
	addr := p.Addr()
	mask := uint8(p.Bits())
	addrL := (mask + 7) / 8

	family := uint16(0)
	optLen := 4 + uint16(addrL)
	b := pool.GetBuf(4 + int(optLen))
	switch {
	case addr.Is4():
		family = family4
		ip := addr.As4()
		copy(b[8:], ip[:])
	case addr.Is6():
		family = family6
		ip := addr.As16()
		copy(b[8:], ip[:])
	default:
		return nil
	}

	bb := b

	// https://tools.ietf.org/html/rfc7871
	// OPTION-CODE, 2 octets, for ECS is 8 (0x00 0x08).
	binary.BigEndian.PutUint16(bb[0:2], 8)              // subnetCode, always 8
	binary.BigEndian.PutUint16(bb[2:4], uint16(optLen)) // length
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
