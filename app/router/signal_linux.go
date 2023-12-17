//go:build linux

package router

import (
	"os"

	"golang.org/x/sys/unix"
)

var exitSig = []os.Signal{unix.SIGHUP, unix.SIGINT, unix.SIGTERM}
