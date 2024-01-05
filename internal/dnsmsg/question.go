package dnsmsg

import (
	"sync"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func unpackQuestion(msg []byte, off int) (*Question, int, error) {
	name, off, err := unpackName(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("name", err)
	}
	typ, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("type", err)
	}
	cls, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("class", err)
	}
	return newQuestion(name, Class(cls), Type(typ)), off, nil
}

type Question struct {
	noCopy
	linkNode

	Name  *pool.Buffer
	Type  Type
	Class Class
}

// no compression len
func (q *Question) len() int {
	l := 0
	l += nameLen(q.Name)
	l += 4 // type and class (2*uint16)
	return l
}

func (q *Question) Copy() *Question {
	cq := NewQuestion(q.Name.B(), q.Class, q.Type)
	return cq
}

// copied from Question.pack
func (q *Question) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := packName(q.Name, msg, off, compression)
	if err != nil {
		return off, newSectionErr("name", err)
	}
	off, err = packUint16(msg, off, uint16(q.Type))
	if err != nil {
		return off, newSectionErr("type", err)
	}
	off, err = packUint16(msg, off, uint16(q.Class))
	if err != nil {
		return off, newSectionErr("class", err)
	}
	return off, nil
}

var qsPool = sync.Pool{
	New: func() any {
		return new(Question)
	},
}

func NewQuestion(name []byte, cls Class, typ Type) *Question {
	return newQuestion(copyBuf(name), cls, typ)
}

func newQuestion(name *pool.Buffer, cls Class, typ Type) *Question {
	q := qsPool.Get().(*Question)
	q.Name = name
	q.Class = cls
	q.Type = typ
	return q
}

func ReleaseQuestion(q *Question) {
	pool.ReleaseBuf(q.Name)
	*q = Question{}
	qsPool.Put(q)
}
