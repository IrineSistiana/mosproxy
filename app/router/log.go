package router

import (
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func inlineQ(q *dnsmsg.Question) zap.Field {
	return zap.Inline((*qLogObj)(q))
}

type qLogObj dnsmsg.Question

func (o *qLogObj) MarshalLogObject(e zapcore.ObjectEncoder) error {
	q := (*dnsmsg.Question)(o)
	e.AddByteString("qname", q.Name.B())
	e.AddUint16("qclass", uint16(q.Class))
	e.AddUint16("qtype", uint16(q.Type))
	return nil
}

const (
	logPackRespErr = "failed to pack resp"
	logPackReqErr  = "failed to pack req"
)
