package pool

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/IrineSistiana/bytespool"
	"github.com/IrineSistiana/gopool"
)

func Go(fn func()) {
	gopool.Go(fn)
}

type Buffer []byte

func GetBuf(size int) Buffer {
	return bytespool.Get(size)
}

func ReleaseBuf(b Buffer) {
	bytespool.Release(b)
}

func CopyBuf(b []byte) Buffer {
	bb := GetBuf(len(b))
	copy(bb, b)
	return bb
}

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

var br1kPool = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 1024) }}

func NewBR1K(r io.Reader) *bufio.Reader {
	br := br1kPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func ReleaseBR1K(br *bufio.Reader) {
	br.Reset(nil)
	br1kPool.Put(br)
}
