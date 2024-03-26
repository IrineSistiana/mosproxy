//go:build !linux

package router

var ctlOk = false

func controlSocket(opt SocketConfig) controlFunc {
	return nil
}
