//go:build !linux && !windows

package transport

func isUdpMsgSizeErr(err error) bool {
	return false
}
