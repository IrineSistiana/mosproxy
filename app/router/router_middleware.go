package router

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
)

type Middleware interface {
	// q will be released and reused, thus Handler MUST NOT access it after Handle() returned.
	Handle(ctx context.Context, q *QueryCtx)

	// io.Closer is optimal. If implemented, will be called when router is shutting down.
}

type PluginCtx struct {
	R      *Router         // Not nil
	Logger *zerolog.Logger // Not nil
}

type NewMiddlewareFunc func(ctx PluginCtx, args map[string]any, next Middleware) (Middleware, error)

var _middlewareReg = middlewareReg{
	factories: make(map[string]NewMiddlewareFunc),
}

type middlewareReg struct {
	m         sync.Mutex
	factories map[string]NewMiddlewareFunc
}

func (mr *middlewareReg) reg(typ string, fn NewMiddlewareFunc) bool {
	mr.m.Lock()
	defer mr.m.Unlock()
	_, dup := mr.factories[typ]
	if dup {
		return false
	}
	mr.factories[typ] = fn
	return true
}

func (mr *middlewareReg) get(typ string) NewMiddlewareFunc {
	mr.m.Lock()
	defer mr.m.Unlock()
	return mr.factories[typ]
}

func RegMiddleware(typ string, fn NewMiddlewareFunc) bool {
	return _middlewareReg.reg(typ, fn)
}

func GetMiddleware(typ string) NewMiddlewareFunc {
	return _middlewareReg.get(typ)
}

func MustRegMiddleware(typ string, fn NewMiddlewareFunc) {
	ok := RegMiddleware(typ, fn)
	if !ok {
		panic(fmt.Sprintf("failed to register middleware [%s]", typ))
	}
}

type middlewareConnector struct {
	next func(ctx context.Context, q *QueryCtx)
}

func (mc *middlewareConnector) Handle(ctx context.Context, q *QueryCtx) {
	mc.next(ctx, q)
}

func (r *Router) initMiddlewares(cfgs []map[string]any) error {
	ms := make([]Middleware, 0, len(cfgs))
	var prevMc *middlewareConnector
	for i, cfg := range cfgs {
		mc := &middlewareConnector{}
		m, err := r.initMiddleware(cfg, mc)
		if err != nil {
			return fmt.Errorf("failed to init middleware #%d, %w", i, err)
		}
		ms = append(ms, m)
		if prevMc != nil {
			prevMc.next = m.Handle
		}
		prevMc = mc
	}

	if prevMc != nil {
		prevMc.next = r.BuiltInHandler
	}
	r.middlewares = ms
	return nil
}

func (r *Router) initMiddleware(cfg map[string]any, next Middleware) (Middleware, error) {
	v := cfg["type"]
	typ, ok := v.(string)
	if !ok {
		return nil, errors.New("missing or invalid middleware type")
	}
	delete(cfg, "type")

	ff := GetMiddleware(typ)
	if ff == nil {
		return nil, fmt.Errorf("unknown middleware type [%s]", typ)
	}
	ctx := PluginCtx{
		R:      r,
		Logger: r.subLoggerForMiddleware(typ),
	}
	m, err := ff(ctx, cfg, next)
	if err != nil {
		return nil, fmt.Errorf("failed to init middleware [%s], %w", typ, err)
	}
	return m, nil
}

func WakeDecode(dst any, src map[string]any, tagName string) error {
	cfg := &mapstructure.DecoderConfig{
		ErrorUnused:      true,
		TagName:          tagName,
		WeaklyTypedInput: true,
		Result:           dst,
	}
	d, err := mapstructure.NewDecoder(cfg)
	if err != nil {
		return err
	}
	return d.Decode(src)
}
