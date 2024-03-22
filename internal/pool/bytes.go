package pool

import (
	"github.com/IrineSistiana/bytespool"
)

type Buffer []byte

func GetBuf(size int) Buffer {
	return bytespool.Get(size)
}

func ReleaseBuf(b Buffer) {
	bytespool.Release(b)
}
