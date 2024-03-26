//go:build linux

package router

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var ctlOk = true

func controlSocket(opt SocketConfig) controlFunc {
	return func(network, _ string, c syscall.RawConn) error {
		var (
			errControl error
			errSyscall error
		)

		errControl = c.Control(func(fd uintptr) {
			if strings.HasPrefix(network, "tcp") || strings.HasPrefix(network, "udp") {
				if opt.SO_REUSEPORT {
					errSyscall = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					if errSyscall != nil {
						errSyscall = os.NewSyscallError("failed to set SO_REUSEPORT", errSyscall)
						return
					}
				}
			}

			if opt.SO_RCVBUF > 0 {
				errSyscall = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, opt.SO_RCVBUF)
				if errSyscall != nil {
					errSyscall = os.NewSyscallError("failed to set SO_RCVBUF", errSyscall)
					return
				}
			}

			if opt.SO_SNDBUF > 0 {
				errSyscall = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, opt.SO_SNDBUF)
				if errSyscall != nil {
					errSyscall = os.NewSyscallError("failed to set SO_SNDBUF", errSyscall)
					return
				}
			}

			if opt.SO_MARK > 0 {
				errSyscall = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, opt.SO_MARK)
				if errSyscall != nil {
					errSyscall = os.NewSyscallError("failed to set SO_MARK", errSyscall)
					return
				}
			}

			if len(opt.SO_BINDTODEVICE) > 0 {
				errSyscall = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, opt.SO_BINDTODEVICE)
				if errSyscall != nil {
					errSyscall = os.NewSyscallError("failed to set SO_BINDTODEVICE", errSyscall)
					return
				}
			}

			if opt._TCP_USER_TIMEOUT > 0 && strings.HasPrefix(network, "tcp") {
				errSyscall = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(opt._TCP_USER_TIMEOUT))
				if errSyscall != nil {
					errSyscall = os.NewSyscallError("failed to set TCP_USER_TIMEOUT", errSyscall)
					return
				}
			}
		})

		if errControl != nil {
			return errControl
		}
		return errSyscall
	}
}
