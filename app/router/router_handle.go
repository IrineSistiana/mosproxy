package router

import (
	"context"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

// always set q.Resp
func (r *Router) handleQuery(q *QueryCtx) {
	// Set info about ECS
	// Priority: client addr < forward client ecs < overwrite
	if r.opt.ECS.Enabled {
		if q.RemoteAddr.IsValid() {
			addr := q.RemoteAddr.Addr().Unmap()
			if addr.Is4() {
				q.ECS2Upstream = netip.PrefixFrom(addr, 24)
			} else {
				q.ECS2Upstream = netip.PrefixFrom(addr, 48)
			}
		}
		if r.opt.ECS.Forward && q.ClientECS.IsValid() { //
			q.ECS2Upstream = q.ClientECS
		}

		// Get zone
		if r.ecsZone != nil {
			m := r.ecsZone.V()
			if m != nil {
				q.ECSZone = m.Mark(q.ECS2Upstream.Addr())
			}
		}

		// Overwrite ecs
		if r.ecsZoneOverwrite != nil {
			m := r.ecsZoneOverwrite.V()
			if m != nil {
				addr, ok := (*m)[q.ECSZone]
				if ok {
					q.ECS2Upstream = addr
				}
			}
		}
	}

	mw := middleware.Load()
	if mw != nil {
		(*mw).Handle(q, r.builtInHandler)
		if q.Resp == nil { // misbehaved
			panic("middleware returned a nil resp")
		}
	} else {
		r.builtInHandler(q)
	}

	if r.opt.Log.Queries {
		r.logAccess(q)
	}
}

func (r *Router) builtInHandler(q *QueryCtx) {
	// Match rules
	var matchedRule *rule
	for i, rule := range r.rules {
		if rule.matcher != nil {
			matcher := rule.matcher.V()
			matched := matcher.Match(&q.Question.Name)
			if rule.reverse {
				matched = !matched
			}
			if !matched {
				continue
			}
		}
		q.Trace.RuleIdx = i
		matchedRule = rule
		break
	}

	if matchedRule == nil {
		setEmptyRespMQ(q, dnsmsg.RCodeRefused)
		return
	}
	if rejectRCode := matchedRule.reject; rejectRCode > 0 {
		setEmptyRespMQ(q, dnsmsg.RCode(rejectRCode))
		return
	}
	if matchedRule.upstream == nil {
		setEmptyRespMQ(q, dnsmsg.RCodeRefused)
		return
	}
	upstream := matchedRule.upstream

	cacheKey := r.cache.Key(q)
	defer pool.ReleaseBuf(cacheKey)

	// lookup mem cache
	resp, t := r.cache.GetMemoryCache(cacheKey)
	if resp != nil { // mem cache hit
		if r.needPrefetch(t) {
			r.asyncSingleFlightPrefetch(cacheKey, q, upstream)
		}
		r.queryCacheHitTotal.Inc()
		q.Resp = resp
		q.Trace.Cached = true
		return
	}

	ctx, cancel := context.WithTimeout(r.ctx, queryTimeout)
	defer cancel()

	// lookup redis cache
	resp, t = r.cache.GetRedisCache(ctx, cacheKey)
	if resp != nil {
		if r.needPrefetch(t) {
			r.asyncSingleFlightPrefetch(cacheKey, q, upstream)
		}
		r.queryCacheHitTotal.Inc()
		q.Resp = resp
		q.Trace.Cached = true
		return
	}

	if ctxDone(ctx) { // check if redis server timed out
		setEmptyRespMQ(q, dnsmsg.RCodeServerFailure)
		return
	}

	err := r.forward(ctx, q, upstream)
	if err != nil {
		r.logger.Warn().
			Str("upstream", upstream.tag).
			Err(err).
			Msg("failed to forward query")
		setEmptyRespMQ(q, dnsmsg.RCodeServerFailure)
		return
	}
	q.Trace.UpstreamTag = upstream.tag

	r.cache.Store(cacheKey, q)
}
