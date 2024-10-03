package router

import "github.com/IrineSistiana/mosproxy/pkg/dnsmsg"

func SetEmptyRespMQ(q *QueryCtx, rcode dnsmsg.RCode) {
	resp := dnsmsg.NewMsg()
	resp.RCode = rcode
	resp.Questions = append(resp.Questions, q.Question.Copy())
	q.SetResp(resp)
}
