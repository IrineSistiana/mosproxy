package router

import (
	"context"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// Middleware MUST NOT keep m and rc. They will be reused.
// The workflow of incoming requests is
// Client -> MiddlewarePreProcessors -> Router's rules (including cache, etc...) --> MiddlewarePostProcessors -> Client
//								\------(MiddlewareHandler has response)---------/
type MiddlewareHandler func(ctx context.Context, m *dnsmsg.Msg, rc *RequestContext)

var (
	// MiddlewarePreProcessors are for pre-processing requests.
	// They will run before the router's rules.
	// MiddlewarePreProcessors can also hijack requests. If a MiddlewareHandler returns a non-nil response. The 
	// subsequent MiddlewareHandlers and router's rules will not run.
	MiddlewarePreProcessors []MiddlewareHandler

	// MiddlewarePostProcessors are for post-processing responses.
	// They will run after the router's rules.
	// MiddlewareHandler MUST NOT set the response to nil.
	MiddlewarePostProcessors []MiddlewareHandler
)

