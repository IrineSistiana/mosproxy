//go:build !linux && !windows

package router

import "os"

var exitSig []os.Signal = nil
