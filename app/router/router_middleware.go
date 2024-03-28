package router

import (
	"context"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// Middleware MUST NOT keep m. They will be reused.
// The workflow of incoming requests is
//
//	Client -> Rules -----------> Cache ---------> MiddlewarePreProcessors -> Upstream -> MiddlewarePostProcessors -\
//		    <-/ (if blocked)   <-/ (if hit)         <-/ (if hijacked)                                             <-/
//
// Middlewares will only be loaded when router is starting.
// DO NOT modify them after router is started.
var (
	// MiddlewarePreProcessors are for pre-processing requests.
	// They will run before requests forwarding to upstream.
	// MiddlewarePreProcessors can also hijack requests. If a MiddlewarePreProcessor returns a non-nil response.
	// The subsequent MiddlewarePreProcessors will not run and the request will not be forwarded.
	// If it returns error, the request will fail immediately.
	MiddlewarePreProcessors []MiddlewarePreProcessor

	// MiddlewarePostProcessors are for post-processing responses.
	// They will run after receiving response from upstream (or MiddlewarePreProcessor, if hijacked).
	// If it returns error, the request will fail immediately.
	MiddlewarePostProcessors []MiddlewarePostProcessor
)

type MiddlewarePreProcessor interface {
	Preprocessing(ctx context.Context, m *dnsmsg.Msg) (*dnsmsg.Msg, error)
}

type MiddlewarePostProcessor interface {
	Postprocessing(ctx context.Context, m *dnsmsg.Msg, resp *dnsmsg.Msg) error
}
