//go:build !linux

package router

import (
	"errors"
)

var errGnetNotSupported = errors.New("gnet backend tcp server only support linux system")

type gnetEngine struct{}

func (gnetEngine) Close() error {
	panic("not impl")
}

func (r *router) startGnetServer(cfg *ServerConfig) (*gnetEngine, error) {
	return nil, errGnetNotSupported
}
