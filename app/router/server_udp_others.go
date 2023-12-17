//go:build !linux

package router

import (
	"errors"
	"net"
)

var errOobHandlerNotImpl = errors.New("oob handler is not impl in this type of system")

func initOobHandler(c *net.UDPConn) (oobSize int, dstReader func(oob []byte) (net.IP, error), srcWriter func(ip net.IP) []byte, _ error) {
	return 0, nil, nil, errOobHandlerNotImpl
}
