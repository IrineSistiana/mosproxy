package dnsmsg

import (
	"sync"
)

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

func (q *Question) packLen(compression map[string]uint16) (int, error) {
	s := 0
	l, err := q.Name.packLen(compression)
	if err != nil {
		return 0, newSectionErr("name", err)
	}
	s += l
	s += 4 // type, class (2*uint16)
	return s, nil
}

func (q *Question) Copy() *Question {
	cq := NewQuestion()
	cq.CopyFrom(q)
	return cq
}

func (q *Question) CopyFrom(q2 *Question) {
	q.Name.CopyFrom(&q2.Name)
	q.Class = q2.Class
	q.Type = q2.Type
}

func (q *Question) Reset() {
	q.Name.Reset()
	q.Class = 0
	q.Type = 0
}

// copied from Question.pack
func (q *Question) pack(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg, err := q.Name.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("name", err)
	}
	msg = packUint16(msg, uint16(q.Type))
	msg = packUint16(msg, uint16(q.Class))
	return msg, nil
}

func UnpackQuestion(msg []byte, off int) (*Question, int, error) {
	q := NewQuestion()
	off, err := q.unpack(msg, off)
	if err != nil {
		ReleaseQuestion(q)
		return nil, off, err
	}
	return q, off, nil
}

// Unpack one question record starting at msg[off:].
// Return next offset, error.
func (q *Question) unpack(msg []byte, off int) (int, error) {
	off, err := q.Name.unpack(msg, off)
	if err != nil {
		return 0, newSectionErr("name", err)
	}
	typ, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("type", err)
	}
	q.Type = Type(typ)
	cls, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("class", err)
	}
	q.Class = Class(cls)
	return off, nil
}

var qsPool = sync.Pool{}

func NewQuestion() *Question {
	q, ok := qsPool.Get().(*Question)
	if !ok {
		q = new(Question)
	}
	return q
}

func ReleaseQuestion(q *Question) {
	q.Reset()
	qsPool.Put(q)
}
