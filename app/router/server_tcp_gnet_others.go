//go:build !linux

package router

import (
	"errors"
)

var errGnetNotSupported = errors.New("gnet backend tcp server only support linux system")

func (r *router) startGnetServer(cfg *ServerConfig) error {
	return errGnetNotSupported
}
