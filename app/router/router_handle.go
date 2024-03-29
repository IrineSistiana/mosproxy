package router

import (
	"context"
	"net/netip"

	"github.com/IrineSistiana/gopool"
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func (r *Router) handleQueryAsync(q *dnsmsg.Msg, qm QueryMeta, w RespWriter) {
	resp, _ := r.handleQueryMsg(q, qm, w)
	if resp != nil {
		w.WriteResp(resp)
		dnsmsg.ReleaseMsg(resp)
	}
}

func (r *Router) handleQuerySync(q *dnsmsg.Msg, qm QueryMeta) (*dnsmsg.Msg, RespMeta) {
	return r.handleQueryMsg(q, qm, nil)
}

// If w != nil, then it run blocking funcs asynchronously, and write resp to w, return nil.
// Otherwise, it returns resp.
func (r *Router) handleQueryMsg(q *dnsmsg.Msg, qm QueryMeta, w RespWriter) (*dnsmsg.Msg, RespMeta) {
	hdr := q.Header
	notImpl := hdr.Response ||
		!hdr.RecursionDesired ||
		hdr.OpCode != dnsmsg.OpCode(0) ||
		len(q.Questions) != 1

	if notImpl {
		e := r.logger.Debug()
		if e != nil {
			e.Stringer("remote", qm.RemoteAddr).
				Stringer("local", qm.LocalAddr).
				Msg("not impl query")
		}
		resp := makeEmptyRespM(q, dnsmsg.RCodeNotImplemented)
		return resp, RespMeta{}

	} else {
		question := q.Questions[0].Copy()
		defer dnsmsg.ReleaseQuestion(question)
		dnsmsg.ToLowerName(question.Name)
		qInfo := getQueryInfo(q)
		resp, meta := r.handleQuery(question, qm, qInfo, w)
		if resp != nil {
			if r.opt.Log.Queries {
				r.logQueryResp(question, qm, qInfo, resp, meta)
			}
		}
		return resp, meta
	}
}

type queryInfo struct {
	id     uint16
	opCode dnsmsg.OpCode
	rd     bool
	edns0  bool
	ecs    netip.Prefix
}

func getQueryInfo(m *dnsmsg.Msg) queryInfo {
	i := queryInfo{
		id:     m.ID,
		opCode: m.OpCode,
		rd:     m.RecursionDesired,
		ecs:    findECS(m),
	}
	for _, rr := range m.Additionals {
		if rr.Hdr().Type == dnsmsg.TypeOPT {
			i.edns0 = true
			break
		}
	}
	return i
}

// Set resp hdr.
// Set/remove resp edns0.
func postProcessResp(qInfo queryInfo, resp *dnsmsg.Msg) {
	resp.Header.ID = qInfo.id
	resp.Header.Response = true
	resp.Header.OpCode = qInfo.opCode
	resp.Header.RecursionAvailable = true
	resp.Header.RecursionDesired = qInfo.rd

	if qInfo.edns0 {
		addOrReplaceOpt(resp, udpSize)
	} else {
		// remove opt from resp
		rr := dnsmsg.PopEDNS0(resp)
		if rr != nil {
			dnsmsg.ReleaseResource(rr)
		}
	}
}

func (r *Router) handleQuery(q *dnsmsg.Question, qMeta QueryMeta, qInfo queryInfo, w RespWriter) (*dnsmsg.Msg, RespMeta) {
	var remoteAddr netip.Addr
	if usefulECS(qInfo.ecs) {
		remoteAddr = qInfo.ecs.Addr()
	} else {
		remoteAddr = qMeta.RemoteAddr.Addr()
	}

	resp, upstream, respMeta := r.nonblockingFuncs(q, remoteAddr)
	if resp != nil {
		postProcessResp(qInfo, resp)
		return resp, respMeta
	}

	if w != nil {
		args := blockingJobArgs{
			r:          r,
			q:          q.Copy(),
			qInfo:      qInfo,
			qMeta:      qMeta,
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
		return r.blockingFuncs(q, qMeta.RemoteAddr.Addr(), respMeta, upstream)
	}
}

type blockingJobArgs struct {
	r          *Router
	q          *dnsmsg.Question
	qInfo      queryInfo
	qMeta      QueryMeta
	remoteAddr netip.Addr
	respMeta   RespMeta
	upstream   *upstreamWrapper
	w          RespWriter
}

func doBlockingJob(a blockingJobArgs) {
	defer dnsmsg.ReleaseQuestion(a.q)
	resp, meta := a.r.blockingFuncs(a.q, a.remoteAddr, a.respMeta, a.upstream)
	defer dnsmsg.ReleaseMsg(resp)
	postProcessResp(a.qInfo, resp)

	if a.r.opt.Log.Queries {
		a.r.logQueryResp(a.q, a.qMeta, a.qInfo, resp, meta)
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
func (r *Router) nonblockingFuncs(q *dnsmsg.Question, remoteAddr netip.Addr) (*dnsmsg.Msg, *upstreamWrapper, RespMeta) {
	var respMeta RespMeta

	// Match rules
	var matchedRule *rule
	for i, rule := range r.rules {
		if rule.matcher != nil {
			matched := rule.matcher.Match(q.Name)
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
		resp := makeEmptyRespMQ(q, uint16(dnsmsg.RCodeRefused))
		return resp, nil, respMeta
	}
	if rejectRCode := matchedRule.reject; rejectRCode > 0 {
		resp := makeEmptyRespMQ(q, rejectRCode)
		return resp, nil, respMeta
	}
	if matchedRule.upstream == nil {
		resp := makeEmptyRespMQ(q, uint16(dnsmsg.RCodeRefused))
		return resp, nil, respMeta
	}

	upstream := matchedRule.upstream

	// lookup cache
	cacheKey, mark := r.cache.Key(q, remoteAddr)
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
func (r *Router) blockingFuncs(q *dnsmsg.Question, remoteAddr netip.Addr, respMeta RespMeta, upstream *upstreamWrapper) (*dnsmsg.Msg, RespMeta) {
	ctx, cancel := context.WithTimeout(r.ctx, queryTimeout)
	defer cancel()

	cacheKey, _ := r.cache.Key(q, remoteAddr)
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
		resp := makeEmptyRespMQ(q, uint16(dnsmsg.RCodeServerFailure))
		return resp, respMeta
	}

	r.limiterAllowN(remoteAddr, costFromUpstream)
	resp, err := r.forward(ctx, upstream, q, remoteAddr)
	if err != nil {
		r.logger.Warn().
			Str("upstream", upstream.tag).
			Err(err).
			Msg("failed to forward query")
		resp := makeEmptyRespMQ(q, uint16(dnsmsg.RCodeServerFailure))
		return resp, respMeta
	}
	r.cache.Store(q, remoteAddr, resp)
	return resp, respMeta
}
