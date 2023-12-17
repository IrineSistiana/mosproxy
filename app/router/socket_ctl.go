package router

import "syscall"

type controlFunc func(network, address string, c syscall.RawConn) error
