package pp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

var sigV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type HeaderV2 struct {
	Command           Command
	TransportProtocol AddressFamilyAndProtocol

	// Note: if TransportProtocol is based on ip, addrs must be valid.
	// If TransportProtocol is inet4, addrs must not be ipv6.
	// Unix addr is not supported.
	SourceAddr      netip.AddrPort
	DestinationAddr netip.AddrPort
}

type Command byte

const (
	LOCAL Command = 0
	PROXY Command = 1
)

type AddressFamilyAndProtocol byte

const (
	UNSPEC AddressFamilyAndProtocol = 0
	TCP4   AddressFamilyAndProtocol = 0x11
	UDP4   AddressFamilyAndProtocol = 0x12
	TCP6   AddressFamilyAndProtocol = 0x21
	UDP6   AddressFamilyAndProtocol = 0x22

	ppHeaderLen  = 16
	inet4AddrLen = 12
	inet6AddrLen = 36
)

func (h *HeaderV2) Size() int {
	switch h.TransportProtocol {
	case TCP4, UDP4:
		return ppHeaderLen + inet4AddrLen
	case TCP6, UDP6:
		return ppHeaderLen + inet6AddrLen
	default:
		return ppHeaderLen
	}
}

func (h *HeaderV2) Put(b []byte) []byte {
	copy(b, sigV2)
	b[12] = byte(h.Command)
	b[13] = byte(h.TransportProtocol)
	switch h.TransportProtocol {
	case TCP4, UDP4:
		binary.BigEndian.PutUint16(b[14:16], inet4AddrLen)
		ip := h.SourceAddr.Addr().As4()
		copy(b[16:20], ip[:])
		ip = h.DestinationAddr.Addr().As4()
		copy(b[20:24], ip[:])
		binary.BigEndian.PutUint16(b[24:26], h.SourceAddr.Port())
		binary.BigEndian.PutUint16(b[26:28], h.DestinationAddr.Port())
	case TCP6, UDP6:
		binary.BigEndian.PutUint16(b[14:16], inet6AddrLen)
		ip := h.SourceAddr.Addr().As16()
		copy(b[16:32], ip[:])
		ip = h.DestinationAddr.Addr().As16()
		copy(b[32:48], ip[:])
		binary.BigEndian.PutUint16(b[48:50], h.SourceAddr.Port())
		binary.BigEndian.PutUint16(b[50:52], h.DestinationAddr.Port())
	default:
		binary.BigEndian.PutUint16(b[14:16], 0)
	}
	return b
}

func ReadV2(r io.Reader) (HeaderV2, int, error) {
	var n int
	b := pool.GetBuf(inet6AddrLen) // enough for header, v4 and v6
	defer pool.ReleaseBuf(b)

	nr, err := io.ReadFull(r, b.B()[:16]) // read 16 bytes header
	n += nr
	if err != nil {
		return HeaderV2{}, n, fmt.Errorf("failed to read pp2 header, %w", err)
	}

	if !bytes.Equal(b.B()[:12], sigV2) { // check protocol signature
		return HeaderV2{}, n, fmt.Errorf("not a pp2 header, invalid protocol signature %x", b.B()[:12])
	}

	var h HeaderV2
	h.Command = Command(b.B()[12])
	h.TransportProtocol = AddressFamilyAndProtocol(b.B()[13])
	addrLen := binary.BigEndian.Uint16(b.B()[14:])

	switch h.TransportProtocol {
	case TCP4, UDP4:
		if addrLen != inet4AddrLen {
			return HeaderV2{}, n, fmt.Errorf("invalid pp2 inet4 addr length, got %d", addrLen)
		}
		nr, err := io.ReadFull(r, b.B()[:inet4AddrLen])
		n += nr
		if err != nil {
			return HeaderV2{}, n, fmt.Errorf("failed to read pp2 inet4 addr, %w", err)
		}
		sa, _ := netip.AddrFromSlice(b.B()[0:4])
		da, _ := netip.AddrFromSlice(b.B()[4:8])
		sp := binary.BigEndian.Uint16(b.B()[8:10])
		dp := binary.BigEndian.Uint16(b.B()[10:12])
		h.SourceAddr = netip.AddrPortFrom(sa, sp)
		h.DestinationAddr = netip.AddrPortFrom(da, dp)
		return h, n, nil
	case TCP6, UDP6:
		if addrLen != inet6AddrLen {
			return HeaderV2{}, n, fmt.Errorf("invalid pp2 inet6 addr length, got %d", addrLen)
		}
		nr, err := io.ReadFull(r, b.B()[:inet6AddrLen])
		n += nr
		if err != nil {
			return HeaderV2{}, n, fmt.Errorf("failed to read pp2 inet6 addr, %w", err)
		}
		sa, _ := netip.AddrFromSlice(b.B()[0:16])
		da, _ := netip.AddrFromSlice(b.B()[16:32])
		sp := binary.BigEndian.Uint16(b.B()[32:34])
		dp := binary.BigEndian.Uint16(b.B()[34:36])
		h.SourceAddr = netip.AddrPortFrom(sa, sp)
		h.DestinationAddr = netip.AddrPortFrom(da, dp)
		return h, n, nil
	case UNSPEC:
		if addrLen > 0 {
			discard := pool.GetBuf(int(addrLen))
			defer pool.ReleaseBuf(discard)
			nr, err := io.ReadFull(r, discard.B())
			n += nr
			if err != nil {
				return HeaderV2{}, n, fmt.Errorf("failed to read pp2 unspec addr, %w", err)
			}
		}
		return h, n, nil
	default:
		return HeaderV2{}, n, fmt.Errorf("unsupported address family and protocol %d", h.TransportProtocol)
	}
}
