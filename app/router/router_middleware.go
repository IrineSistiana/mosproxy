package router

import (
	"context"
	"sync/atomic"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// Middleware MUST NOT keep m. They will be reused.
// The workflow of incoming requests is
//
//	Client --> PreHandling ------> Rules ----------> Cache ---------> Preprocessing -> Upstream -> Postprocessing -\
//		      <-/ (if has resp)  <-/ (if blocked)   <-/ (if hit)      <-/ (if has resp)                          <-/
//

type Middleware interface {
	// Handle query msg right after receiving.
	// Note: This func should be fast and MUST NOT contain block operations. It will
	// be called directly in the main network thread in UDP/Gnet server.
	PreHandling(m *dnsmsg.Msg, qMeta QueryMeta) (resp *dnsmsg.Msg, err error)

	// Handle query msg before sending to upstream.
	PreForwarding(ctx context.Context, m *dnsmsg.Msg, qMeta QueryMeta, qInfo QueryInfo) (resp *dnsmsg.Msg, err error)

	// Handle query and response after received from upstream.
	PostForwarding(ctx context.Context, q *dnsmsg.Question, qMeta QueryMeta, qInfo QueryInfo, resp *dnsmsg.Msg) error
}

func SetMiddleware(m Middleware) {
	if m == nil {
		middlewareP.Store(&nop)
	}
	p := &m
	middlewareP.Store(p)
}

func middlewareImpl() Middleware {
	p := middlewareP.Load()
	if p == nil {
		return nop
	}
	return *p
}

var middlewareP atomic.Pointer[Middleware]

var nop Middleware = nopMiddleWare{}

type nopMiddleWare struct{}

func (nopMiddleWare) PreHandling(m *dnsmsg.Msg, qMeta QueryMeta) (*dnsmsg.Msg, error) {
	return nil, nil
}

func (nopMiddleWare) PreForwarding(ctx context.Context, m *dnsmsg.Msg, qMeta QueryMeta, qInfo QueryInfo) (*dnsmsg.Msg, error) {
	return nil, nil
}

func (nopMiddleWare) PostForwarding(ctx context.Context, q *dnsmsg.Question, qMeta QueryMeta, qInfo QueryInfo, resp *dnsmsg.Msg) error {
	return nil
}
