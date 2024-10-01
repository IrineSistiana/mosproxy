//go:build !linux

package router

var socketCtlOk = false

func controlSocket(opt SocketConfig) controlFunc {
	return nil
}
