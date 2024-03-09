package dnsmsg

import (
	"sync"
)

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

// no compression Len
func (q *Question) Len() int {
	l := 0
	l += q.Name.PackLen()
	l += 4 // type and class (2*uint16)
	return l
}

func (q *Question) Copy() *Question {
	cq := NewQuestion()
	cq.Name = Name(copyBuf(q.Name))
	cq.Class = q.Class
	cq.Type = q.Type
	return cq
}

// copied from Question.pack
func (q *Question) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := q.Name.pack(msg, off, compression)
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
	q := NewQuestion()
	q.Name = name
	q.Type = Type(typ)
	q.Class = Class(cls)
	return q, off, nil
}

var qsPool = sync.Pool{
	New: func() any {
		return new(Question)
	},
}

func NewQuestion() *Question {
	return qsPool.Get().(*Question)
}

func ReleaseQuestion(q *Question) {
	if q.Name != nil {
		ReleaseName(q.Name)
	}
	*q = Question{}
	qsPool.Put(q)
}
