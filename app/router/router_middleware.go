package router

import (
	"sync/atomic"
)

type Middleware interface {
	// q.Resp must be set upon returning.
	// builtin will set the q.Resp upon returning.
	// q will be released and reused, thus it MUST NOT be used after Handle() returning.
	Handle(q *QueryCtx, builtin func(q *QueryCtx))
}

var middleware atomic.Pointer[Middleware]

// Set the middleware.
// if nil, clear the middleware.
func SetMiddleware(m Middleware) {
	if m == nil {
		middleware.Store(nil)
	}
	p := &m
	middleware.Store(p)
}
