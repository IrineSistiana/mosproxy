//go:build !linux

package router

import (
	"errors"
)

func (r *router) startGnetServer(cfg *ServerConfig) error {
	return errors.New("gnet backend tcp server only support linux system")
}
