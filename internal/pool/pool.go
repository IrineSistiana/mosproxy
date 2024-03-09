package pool

import (
	"bytes"
	"fmt"
	"sync"
)

type BytesBufPool struct {
	p sync.Pool
}

func NewBytesBufPool(initSize int) *BytesBufPool {
	if initSize < 0 {
		panic(fmt.Sprintf("utils.NewBytesBufPool: negative init size %d", initSize))
	}

	return &BytesBufPool{
		p: sync.Pool{New: func() any {
			b := new(bytes.Buffer)
			b.Grow(initSize)
			return b
		}},
	}
}

func (p *BytesBufPool) Get() *bytes.Buffer {
	return p.p.Get().(*bytes.Buffer)
}

func (p *BytesBufPool) Release(b *bytes.Buffer) {
	b.Reset()
	p.p.Put(b)
}
