//go:build linux

package udpcmsg

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

func Ok() bool {
	return true
}

// Set socket option to receive local addr in oob.
// Inet6 is true if c is an inet6 connection and IPV6_RECVPKTINFO was set.
// otherwise, c is an inet4 connection and IP_PKTINFO was set.
func SetOpt(c *net.UDPConn) (inet6 bool, err error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return false, err
	}

	var innerErr error
	err = sc.Control(func(fd uintptr) {
		so_domain, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			innerErr = fmt.Errorf("failed to get SO_DOMAIN, %w", err)
			return
		}

		switch so_domain {
		case unix.AF_INET:
			inet6 = false
			err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			if err != nil {
				innerErr = fmt.Errorf("failed to set IP_PKTINFO, %w", err)
				return
			}
		case unix.AF_INET6:
			inet6 = true
			err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
			if err != nil {
				innerErr = fmt.Errorf("failed to set IPV6_RECVPKTINFO, %w", err)
				return
			}
		default:
			innerErr = fmt.Errorf("socket protocol %d is not supported", so_domain)
			return
		}
	})
	if err != nil {
		return false, err
	}
	return inet6, innerErr
}

type errShortBuffer struct {
	section string
}

func (e *errShortBuffer) Error() string {
	return fmt.Sprintf("short buffer for section %s", e.section)
}

// Parses local addr from oob control msgs. May return invalid addr and nil error if no
// local addr info was found.
func ParseLocalAddr(oob []byte) (netip.Addr, error) {
	remain := oob
	for len(remain) > 0 {
		if len(oob) < unix.SizeofCmsghdr {
			return netip.Addr{}, &errShortBuffer{section: "Cmsghdr"}
		}
		var (
			hdr  unix.Cmsghdr
			data []byte
			err  error
		)
		hdr, data, remain, err = unix.ParseOneSocketControlMessage(remain)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to parse cmsg, %w", err)
		}

		if hdr.Level == unix.IPPROTO_IP && hdr.Type == unix.IP_PKTINFO { // inet
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, &errShortBuffer{section: "Inet4Pktinfo"}
			}
			m := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom4(m.Addr), nil
		}

		if hdr.Level == unix.IPPROTO_IPV6 && hdr.Type == unix.IPV6_PKTINFO { // inet6
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, &errShortBuffer{section: "Inet6Pktinfo"}
			}
			m := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom16(m.Addr), nil
		}
	}
	return netip.Addr{}, nil
}

// Cmsg size for addr. If addr is invalid, returns 0.
func CmsgSize(addr netip.Addr) int {
	if !addr.IsValid() {
		return 0
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return unix.CmsgSpace(unix.SizeofInet4Pktinfo)
	}
	return unix.CmsgSpace(unix.SizeofInet6Pktinfo)
}

// Pack addr into a control msg (Inet[4|6]Pktinfo).
// b is the buffer for packing, if b is not big enough (or nil), a new slice
// will be allocated.
// Invalid addr returns nil.
func CmsgPktInfo(b []byte, addr netip.Addr) []byte {
	if !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return cmsgInet4Pktinfo(b, addr)
	}
	return cmsgInet6Pktinfo(b, addr)
}

func cmsgInet6Pktinfo(b []byte, addr netip.Addr) []byte {
	if s := unix.CmsgSpace(unix.SizeofInet6Pktinfo); len(b) < s {
		b = make([]byte, s)
	} else {
		b = b[:s]
	}

	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	h.Level = unix.IPPROTO_IPV6
	h.Type = unix.IPV6_PKTINFO
	data := b[unix.CmsgLen(0):]
	m := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0]))
	m.Addr = addr.As16()
	m.Ifindex = 0
	return b
}

func cmsgInet4Pktinfo(b []byte, addr netip.Addr) []byte {
	if s := unix.CmsgSpace(unix.SizeofInet4Pktinfo); len(b) < s {
		b = make([]byte, s)
	} else {
		b = b[:s]
	}

	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_PKTINFO
	data := b[unix.CmsgLen(0):]
	m := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
	m.Ifindex = 0
	m.Spec_dst = addr.As4()
	m.Addr = [4]byte{} // b may contain garbage data. Zero it.
	return b
}
