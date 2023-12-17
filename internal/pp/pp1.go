package pp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"
)

type HeaderV1 struct {
	TcpVersion      uint8 // 4 or 6
	SourceAddr      netip.AddrPort
	DestinationAddr netip.AddrPort
}

var ErrInvalidPP1Header = errors.New("invalid protocol proxy v1 header")

// Note: r should have at least 107 bytes buffer to read the longest header.
func ReadV1(r *bufio.Reader) (h HeaderV1, _ error) {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return h, err
	}
	return ParseV1(b)
}

func ParseV1(b []byte) (h HeaderV1, _ error) {
	if len(b) < 6 || string(b[len(b)-2:]) != "\r\n" {
		return h, ErrInvalidPP1Header
	}
	b = b[:len(b)-2]

	var secOff [5]int
	var off int
	for n := 0; n < 5; n++ {
		i := bytes.IndexByte(b[off:], ' ')
		if i <= 0 {
			return h, ErrInvalidPP1Header
		}
		off = off + i + 1
		secOff[n] = off
	}

	// PROXY prefix
	s := b[:secOff[0]-1]
	if string(s) != "PROXY" {
		return h, fmt.Errorf("invalid pp1 prefix, got [%s]", s)
	}

	// TCP4/TCP6
	s = b[secOff[0] : secOff[1]-1]
	if string(s) == "TCP4" {
		h.TcpVersion = 4
	} else if string(s) == "TCP6" {
		h.TcpVersion = 6
	} else {
		return h, fmt.Errorf("invalid pp1 protocol [%s]", s)
	}

	// Src
	s = b[secOff[1] : secOff[2]-1]
	src, err := netip.ParseAddr(bytes2StrUnsafe(s))
	if err != nil {
		return h, fmt.Errorf("invalid src addr [%s], %w", s, err)
	}

	// Dst
	s = b[secOff[2] : secOff[3]-1]
	dst, err := netip.ParseAddr(bytes2StrUnsafe(s))
	if err != nil {
		return h, fmt.Errorf("invalid dst addr [%s], %w", s, err)
	}

	// Src port
	s = b[secOff[3] : secOff[4]-1]
	sp, err := strconv.ParseUint(bytes2StrUnsafe(s), 0, 16)
	if err != nil {
		return h, fmt.Errorf("invalid src port [%s], %w", s, err)
	}

	// Dst port
	s = b[secOff[4]:]
	dp, err := strconv.ParseUint(bytes2StrUnsafe(s), 0, 16)
	if err != nil {
		return h, fmt.Errorf("invalid dst port [%s], %w", s, err)
	}

	h.SourceAddr = netip.AddrPortFrom(src, uint16(sp))
	h.DestinationAddr = netip.AddrPortFrom(dst, uint16(dp))
	return h, nil
}

func bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
