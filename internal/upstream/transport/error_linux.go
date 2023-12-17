//go:build linux

package transport

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func isUdpMsgSizeErr(err error) bool {
	return errors.Is(err, syscall.Errno(unix.EMSGSIZE))
}
