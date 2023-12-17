//go:build !linux

package router

func controlSocket(opt SocketConfig) controlFunc {
	return nil
}
