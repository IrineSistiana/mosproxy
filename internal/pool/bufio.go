package pool

import (
	"bufio"
	"io"
	"sync"
)

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
