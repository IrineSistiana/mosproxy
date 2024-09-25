package router

import "github.com/IrineSistiana/mosproxy/pkg/dnsmsg"

func SetEmptyRespMQ(q *QueryCtx, rcode dnsmsg.RCode) {
	if q.Resp != nil {
		dnsmsg.ReleaseMsg(q.Resp)
		q.Resp = nil
	}
	resp := dnsmsg.NewMsg()
	resp.RCode = rcode
	resp.Questions = append(resp.Questions, q.Question.Copy())
	q.Resp = resp
}
