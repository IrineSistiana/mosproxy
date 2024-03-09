package pool

import (
	"github.com/IrineSistiana/bytespool"
	"github.com/IrineSistiana/gopool"
)

type Buffer []byte

func GetBuf(size int) Buffer {
	return bytespool.Get(size)
}

func ReleaseBuf(b Buffer) {
	bytespool.Release(b)
}

func Go(fn func()) {
	gopool.Go(fn)
}
