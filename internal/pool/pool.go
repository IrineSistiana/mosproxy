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

type SyncPool[T any] struct {
	opts SyncPoolOpts[T]
	sp   sync.Pool
}

type SyncPoolOpts[T any] struct {
	New       func() *T // If nil, will be new(T)
	OnRelease func(v *T)
	OnGet     func(v *T)
}

func NewSyncPool[T any](opts SyncPoolOpts[T]) *SyncPool[T] {
	return &SyncPool[T]{
		opts: opts,
	}
}

func (p *SyncPool[T]) Get() *T {
	v, ok := p.sp.Get().(*T)
	if !ok {
		if f := p.opts.New; f != nil {
			v = f()
		} else {
			v = new(T)
		}
	}
	if f := p.opts.OnGet; f != nil {
		f(v)
	}
	return v
}

func (p *SyncPool[T]) Release(v *T) {
	if f := p.opts.OnRelease; f != nil {
		f(v)
	}
	p.sp.Put(v)
}
