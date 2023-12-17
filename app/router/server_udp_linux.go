//go:build linux

package router

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

var (
	oobSizeV4 = len(ipv4.NewControlMessage(ipv4.FlagDst))
	oobSizeV6 = len(ipv6.NewControlMessage(ipv6.FlagDst))
)

var (
	errCmNoDstAddr = errors.New("control msg does not have dst address")
)

func ip2CmSrc(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		return (&ipv4.ControlMessage{
			Src: ip,
		}).Marshal()
	}

	if ip6 := ip.To16(); ip6 != nil {
		return (&ipv6.ControlMessage{
			Src: ip,
		}).Marshal()
	}
	return nil
}

func readDst4(readOob []byte) (net.IP, error) {
	var cm ipv4.ControlMessage
	if err := cm.Parse(readOob); err != nil {
		return nil, err
	}
	if cm.Dst == nil {
		return nil, errCmNoDstAddr
	}
	return cm.Dst, nil
}

func readDst6(readOob []byte) (net.IP, error) {
	var cm ipv6.ControlMessage
	if err := cm.Parse(readOob); err != nil {
		return nil, err
	}
	if cm.Dst == nil {
		return nil, errCmNoDstAddr
	}
	return cm.Dst, nil
}

func initOobHandler(c *net.UDPConn) (oobSize int, dstReader func(oob []byte) (net.IP, error), srcWriter func(ip net.IP) []byte, _ error) {
	if !c.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		return 0, nil, nil, nil
	}

	sc, err := c.SyscallConn()
	if err != nil {
		return 0, nil, nil, err
	}

	var controlErr error
	if err := sc.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			controlErr = os.NewSyscallError("failed to get SO_DOMAIN", err)
			return
		}
		switch v {
		case unix.AF_INET:
			c4 := ipv4.NewPacketConn(c)
			if err := c4.SetControlMessage(ipv4.FlagDst, true); err != nil {
				controlErr = fmt.Errorf("failed to set ipv4 cmsg flags, %w", err)
			}
			oobSize = oobSizeV4
			dstReader = readDst4
			srcWriter = ip2CmSrc
			return
		case unix.AF_INET6:
			c6 := ipv6.NewPacketConn(c)
			if err := c6.SetControlMessage(ipv6.FlagDst, true); err != nil {
				controlErr = fmt.Errorf("failed to set ipv6 cmsg flags, %w", err)
			}
			oobSize = oobSizeV6
			dstReader = readDst6
			srcWriter = ip2CmSrc
			return
		default:
			controlErr = fmt.Errorf("socket protocol %d is not supported", v)
		}
	}); err != nil {
		return 0, nil, nil, fmt.Errorf("control fd err, %w", controlErr)
	}

	if controlErr != nil {
		return 0, nil, nil, fmt.Errorf("failed to set up socket, %w", controlErr)
	}
	return
}
