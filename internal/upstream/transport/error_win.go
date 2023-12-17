//go:build windows

package transport

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isUdpMsgSizeErr(err error) bool {
	return errors.Is(err, syscall.Errno(windows.WSAEMSGSIZE))
}
