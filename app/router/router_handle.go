package router

import (
	"context"
	"net/netip"

	"github.com/IrineSistiana/gopool"
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func (r *Router) handleQueryAsync(q *dnsmsg.Msg, qm QueryMeta, w RespWriter) {
	resp := r.handleQueryMsg(q, qm, w)
	if resp != nil {
		w.WriteResp(resp)
		dnsmsg.ReleaseMsg(resp)
	}
}

func (r *Router) handleQuerySync(q *dnsmsg.Msg, qm QueryMeta) *dnsmsg.Msg {
	return r.handleQueryMsg(q, qm, nil)
}

// If w != nil, then it run blocking funcs asynchronously, and write resp to w, return nil.
// Otherwise, it returns resp.
func (r *Router) handleQueryMsg(q *dnsmsg.Msg, qMeta QueryMeta, w RespWriter) *dnsmsg.Msg {
	resp, err := middlewareImpl().PreHandling(q, qMeta)
	if err != nil {
		r.logger.Warn().Err(err).Msg("middleware pre-handling error")
		return makeEmptyRespM(q, dnsmsg.RCodeServerFailure)
	}
	if resp != nil {
		postProcessResp(getQueryInfo(q), resp)
		return resp
	}

	hdr := q.Header
	notImpl := hdr.Response ||
		!hdr.RecursionDesired ||
		hdr.OpCode != dnsmsg.OpCode(0) ||
		len(q.Questions) != 1

	if notImpl {
		e := r.logger.Debug()
		if e != nil {
			e.Stringer("remote", qMeta.RemoteAddr).
				Stringer("local", qMeta.LocalAddr).
				Msg("not impl query")
		}
		return makeEmptyRespM(q, dnsmsg.RCodeNotImplemented)

	} else {
		qc := qCtx{
			q:     q.Questions[0].Copy(),
			qMeta: qMeta,
			qInfo: getQueryInfo(q)}
		defer dnsmsg.ReleaseQuestion(qc.q)
		dnsmsg.ToLowerName(qc.q.Name)

		resp, meta := r.handleQuestion(qc, w)
		if resp != nil {
			postProcessResp(qc.qInfo, resp)
			if r.opt.Log.Queries {
				r.logQueryResp(qc, resp, meta)
			}
		}
		return resp
	}
}

func getQueryInfo(m *dnsmsg.Msg) QueryInfo {
	i := QueryInfo{
		Id:     m.ID,
		OpCode: m.OpCode,
		Rd:     m.RecursionDesired,
		ECS:    findECS(m),
	}
	for _, rr := range m.Additionals {
		if rr.Hdr().Type == dnsmsg.TypeOPT {
			i.EDNS0 = true
			break
		}
	}
	return i
}

// Set resp hdr.
// Set/remove resp edns0.
func postProcessResp(qInfo QueryInfo, resp *dnsmsg.Msg) {
	resp.Header.ID = qInfo.Id
	resp.Header.Response = true
	resp.Header.OpCode = qInfo.OpCode
	resp.Header.RecursionAvailable = true
	resp.Header.RecursionDesired = qInfo.Rd

	if qInfo.EDNS0 {
		addOrReplaceOpt(resp, udpSize)
	} else {
		// remove opt from resp
		rr := dnsmsg.PopEDNS0(resp)
		if rr != nil {
			dnsmsg.ReleaseResource(rr)
		}
	}
}

func (r *Router) handleQuestion(q qCtx, w RespWriter) (*dnsmsg.Msg, RespMeta) {
	var remoteAddr netip.Addr
	if usefulECS(q.qInfo.ECS) {
		remoteAddr = q.qInfo.ECS.Addr()
	} else {
		remoteAddr = q.qMeta.RemoteAddr.Addr()
	}

	resp, upstream, respMeta := r.nonblockingFuncs(q, remoteAddr)
	if resp != nil {
		return resp, respMeta
	}

	if w != nil {
		args := blockingJobArgs{
			r: r,
			q: qCtx{
				q:     q.q.Copy(),
				qMeta: q.qMeta,
				qInfo: q.qInfo,
			},
			remoteAddr: remoteAddr,
			respMeta:   respMeta,
			upstream:   upstream,
			w:          w,
		}
		r.bJobPool.GoJob(gopool.Job[blockingJobArgs]{
			Args: args,
			Fn:   doBlockingJob,
		})
		return nil, RespMeta{}
	} else {
		return r.blockingFuncs(qCtx{q: q.q, qMeta: q.qMeta, qInfo: q.qInfo}, remoteAddr, respMeta, upstream)
	}
}

type blockingJobArgs struct {
	r          *Router
	q          qCtx
	remoteAddr netip.Addr
	respMeta   RespMeta
	upstream   *upstreamWrapper
	w          RespWriter
}

func doBlockingJob(a blockingJobArgs) {
	defer dnsmsg.ReleaseQuestion(a.q.q)
	resp, meta := a.r.blockingFuncs(a.q, a.remoteAddr, a.respMeta, a.upstream)
	defer dnsmsg.ReleaseMsg(resp)
	postProcessResp(a.q.qInfo, resp)

	if a.r.opt.Log.Queries {
		a.r.logQueryResp(a.q, resp, meta)
	}

	a.w.WriteResp(resp)
}

func usefulECS(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() {
		return bits >= 24
	}
	return bits >= 48 // v6
}

// return (resp, nil, meta)
// or (nil, upstream, meta)
func (r *Router) nonblockingFuncs(q qCtx, remoteAddr netip.Addr) (*dnsmsg.Msg, *upstreamWrapper, RespMeta) {
	var respMeta RespMeta

	// Match rules
	var matchedRule *rule
	for i, rule := range r.rules {
		if rule.matcher != nil {
			matched := rule.matcher.Match(q.q.Name)
			if rule.reverse {
				matched = !matched
			}
			if !matched {
				continue
			}
		}
		respMeta.RuleIdx = i
		matchedRule = rule
		break
	}

	if matchedRule == nil {
		resp := makeEmptyRespMQ(q.q, uint16(dnsmsg.RCodeRefused))
		return resp, nil, respMeta
	}
	if rejectRCode := matchedRule.reject; rejectRCode > 0 {
		resp := makeEmptyRespMQ(q.q, rejectRCode)
		return resp, nil, respMeta
	}
	if matchedRule.upstream == nil {
		resp := makeEmptyRespMQ(q.q, uint16(dnsmsg.RCodeRefused))
		return resp, nil, respMeta
	}

	upstream := matchedRule.upstream

	// lookup cache
	cacheKey, mark := r.cache.Key(q.q, remoteAddr)
	respMeta.IpMark = mark
	resp, storedTime, expireTime := r.cache.GetMemoryCache(cacheKey)
	pool.ReleaseBuf(cacheKey)
	if resp != nil { // mem cache hit
		if needPrefetch(storedTime, expireTime) {
			r.asyncSingleFlightPrefetch(q, remoteAddr, upstream)
		}
		r.queryCacheHitTotal.Inc()
		r.limiterAllowN(remoteAddr, costFromCache)
		respMeta.Cached = true
		return resp, nil, respMeta
	}
	return nil, upstream, respMeta
}

// always returns a resp
func (r *Router) blockingFuncs(q qCtx, remoteAddr netip.Addr, respMeta RespMeta, upstream *upstreamWrapper) (*dnsmsg.Msg, RespMeta) {
	ctx, cancel := context.WithTimeout(r.ctx, queryTimeout)
	defer cancel()

	cacheKey, _ := r.cache.Key(q.q, remoteAddr)
	resp, storedTime, expireTime := r.cache.GetRedisCache(ctx, cacheKey)
	pool.ReleaseBuf(cacheKey)
	if resp != nil {
		if needPrefetch(storedTime, expireTime) {
			r.asyncSingleFlightPrefetch(q, remoteAddr, upstream)
		}
		r.queryCacheHitTotal.Inc()
		r.limiterAllowN(remoteAddr, costFromCache)
		respMeta.Cached = true
		return resp, respMeta
	}

	if ctxDone(ctx) { // check if redis server timed out
		resp := makeEmptyRespMQ(q.q, uint16(dnsmsg.RCodeServerFailure))
		return resp, respMeta
	}

	r.limiterAllowN(remoteAddr, costFromUpstream)
	resp, err := r.forward(ctx, q, remoteAddr, upstream)
	if err != nil {
		r.logger.Warn().
			Str("upstream", upstream.tag).
			Err(err).
			Msg("failed to forward query")
		resp := makeEmptyRespMQ(q.q, uint16(dnsmsg.RCodeServerFailure))
		return resp, respMeta
	}

	err = middlewareImpl().PostForwarding(ctx, q.q, q.qMeta, q.qInfo, resp)
	if err != nil {
		dnsmsg.ReleaseMsg(resp)
		r.logger.Warn().
			Err(err).
			Msg("postprocessor error")
		return nil, respMeta
	}

	r.cache.Store(q.q, remoteAddr, resp)
	return resp, respMeta
}
