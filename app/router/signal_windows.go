//go:build windows

package router

import (
	"os"

	"golang.org/x/sys/windows"
)

var exitSig = []os.Signal{windows.SIGHUP, windows.SIGINT, windows.SIGTERM}
