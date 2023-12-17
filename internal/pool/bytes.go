package pool

import (
	"fmt"
	"math/bits"
	"sync"
)

var _ZeroBuffer *Buffer = &Buffer{b: make([]byte, 0)}

// Nil Buffer is a valid buffer. It's Len/Cap will return 0.
// It's B returns a nil []byte.
type Buffer struct {
	b []byte
}

// If b is nil, then B returns nil.
func (b *Buffer) B() []byte {
	if b == nil {
		return nil
	}
	return b.b
}

// If b is nil, then Len returns 0.
func (b *Buffer) Len() int {
	if b == nil {
		return 0
	}
	return len(b.b)
}

// If b is nil, then Cap returns 0.
func (b *Buffer) Cap() int {
	if b == nil {
		return 0
	}
	return cap(b.b)
}

func (b *Buffer) ApplySize(n int) {
	b.b = b.b[:n]
}

// Note: The maximum reusable size is 2^30 (1GBytes).
// If size is too big, GetBuf simply calls make([]byte,size) and
// ReleaseBuf is a noop.
func GetBuf(size int) *Buffer {
	return _globalPool.get(size)
}

func ReleaseBuf(b *Buffer) {
	_globalPool.release(b)
}

var _globalPool = newPool()

type pool struct {
	sp smallPool
	lp largePool
}

func newPool() *pool {
	p := new(pool)
	initSmallPool(&p.sp)
	initLargePool(&p.lp)
	return p
}

func (p *pool) get(size int) *Buffer {
	switch {
	case size <= 0:
		return _ZeroBuffer
	case size <= 1<<8:
		return p.sp.get(size)
	case size <= 1<<30:
		return p.lp.get(size)
	default:
		b := make([]byte, size)
		return &Buffer{
			b: b,
		}
	}
}

func (p *pool) release(b *Buffer) {
	if b == nil { // valid 0 buffer
		return
	}
	c := b.Cap()
	switch {
	case c == 0:
		// Should be _ZeroBuffer.
		return
	case c <= 1<<8:
		p.sp.release(b)
		return
	case c <= 1<<30:
		p.lp.release(b)
		return
	default:
		return
	}
}

// 1~2^8(256)
type smallPool struct {
	ps [9]sync.Pool
}

func initSmallPool(p *smallPool) {
	for i := range p.ps {
		bufSize := spSize(i)
		p.ps[i].New = func() any {
			return &Buffer{
				b: make([]byte, bufSize),
			}
		}
	}
}

func spIdx(size int) int {
	return bits.Len(uint(size - 1))
}

func spSize(idx int) int {
	return 1 << idx
}

func (p *smallPool) get(size int) *Buffer {
	i := spIdx(size)
	b := p.ps[i].Get().(*Buffer)
	b.ApplySize(size)
	return b
}

func (p *smallPool) release(b *Buffer) {
	c := b.Cap()
	i := spIdx(c)
	if c != spSize(i) {
		panic(fmt.Sprintf("buf release: invalid cap %d, pool %d", c, i))
	}
	p.ps[i].Put(b)
}

// 2^8(257) ~ 2^30
type largePool struct {
	ps [22][4]sync.Pool
}

func initLargePool(p *largePool) {
	for h := range p.ps {
		for l := range p.ps[h] {
			bufSize := lpSize(h, l)
			p.ps[h][l].New = func() any {
				return &Buffer{
					b: make([]byte, bufSize),
				}
			}
		}
	}
}

func lpIdx(size int) (int, int) {
	b := bits.Len(uint(size - 1))
	l := ((size - 1) >> (b - 3)) & 0b11
	h := b - 9
	return h, l
}

func lpSize(h, l int) int {
	return 1<<(h+8) + (l+1)<<(h+6)
}

func (p *largePool) get(size int) *Buffer {
	h, l := lpIdx(size)
	b := p.ps[h][l].Get().(*Buffer)
	b.ApplySize(size)
	return b
}

func (p *largePool) release(b *Buffer) {
	c := b.Cap()
	h, l := lpIdx(c)
	if c != lpSize(h, l) {
		panic(fmt.Sprintf("buf release: invalid cap %d, pool %d.%d", c, h, l))
	}
	p.ps[h][l].Put(b)
}
