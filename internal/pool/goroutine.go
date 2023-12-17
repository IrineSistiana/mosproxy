package pool

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"go.uber.org/zap"
)

var _globalGoPool = newGoPool()

func Go(fn func()) {
	_globalGoPool.Go(fn)
}

func GoPoolSize() int {
	return _globalGoPool.Size()
}

func GoPoolGoCreated() uint64 {
	return _globalGoPool.GoCreated()
}

func GoPoolGoReused() uint64 {
	return _globalGoPool.GoReused()
}

type gcNotify struct {
	c       chan time.Time
	stopped atomic.Bool
}

func newGcNotify() *gcNotify {
	n := &gcNotify{
		c: make(chan time.Time, 1),
	}
	runtime.SetFinalizer(&sentinel{n: n}, sentinelFinalizer)
	return n
}

func (n *gcNotify) Stop() {
	n.stopped.Store(true)
}

func (n *gcNotify) C() <-chan time.Time {
	return n.c
}

type sentinel struct {
	n *gcNotify
}

func sentinelFinalizer(s *sentinel) {
	if s.n.stopped.Load() {
		return
	}
	select {
	case s.n.c <- time.Now():
	default:
	}
	runtime.SetFinalizer(s, sentinelFinalizer) // loop forever
}

const goPoolSubPoolNum = 4

type goPool struct {
	sub [goPoolSubPoolNum]goSubPool

	closeOnce   sync.Once
	closeNotify chan struct{}
	gcNotify    *gcNotify
}

// Note: A pool must be closed to release the gc loop goroutine.
func newGoPool() *goPool {
	p := &goPool{
		closeNotify: make(chan struct{}),
		gcNotify:    newGcNotify(),
	}

	go p.gcLoop()
	return p
}

func (p *goPool) Go(fn func()) {
	p.sub[utils.FastRand()%goPoolSubPoolNum].Go(fn)
}

func (p *goPool) gcLoop() {
	for {
		select {
		case <-p.closeNotify:
			return
		case <-p.gcNotify.C():
			for i := range p.sub {
				p.sub[i].gc()
			}

			mlog.L().Check(zap.DebugLevel, "go pool gc finished").Write(
				zap.Int("size", p.Size()),
				zap.Uint64("go_created", p.GoCreated()),
				zap.Uint64("go_reused", p.GoReused()),
			)
		}
	}
}

func (p *goPool) Size() (n int) {
	for i := range p.sub {
		n += p.sub[i].Size()
	}
	return n
}

func (p *goPool) GoCreated() uint64 {
	var n uint64
	for i := range p.sub {
		n += p.sub[i].GoCreated()
	}
	return n
}
func (p *goPool) GoReused() uint64 {
	var n uint64
	for i := range p.sub {
		n += p.sub[i].GoReused()
	}
	return n
}

func (p *goPool) Close() {
	p.closeOnce.Do(func() {
		for i := range p.sub {
			p.sub[i].Close()
		}
		close(p.closeNotify)
		p.gcNotify.Stop()
	})
}

type goSubPool struct {
	m                    sync.Mutex
	p                    []*goWorker
	minIdleSinceLatestGC int
	closed               bool

	goCreated atomic.Uint64
	goReused  atomic.Uint64
}

func (p *goSubPool) Size() int {
	p.m.Lock()
	defer p.m.Unlock()
	return len(p.p)
}

func (p *goSubPool) GoCreated() uint64 {
	return p.goCreated.Load()
}

func (p *goSubPool) GoReused() uint64 {
	return p.goReused.Load()
}

func (p *goSubPool) Go(fn func()) {
	var w *goWorker
	// pop a worker
	p.m.Lock()
	if len(p.p) > 0 {
		w = p.p[len(p.p)-1]
		p.p[len(p.p)-1] = nil
		p.p = p.p[:len(p.p)-1]
		if len(p.p) < p.minIdleSinceLatestGC {
			p.minIdleSinceLatestGC = len(p.p)
		}
	}
	p.m.Unlock()

	if w == nil {
		p.goCreated.Add(1)
		p.newWorker(fn)
	} else {
		p.goReused.Add(1)
		select {
		case w.job <- fn:
		default:
			panic("blocked job chan")
		}
	}
}

func (p *goSubPool) Close() {
	p.m.Lock()
	defer p.m.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for _, w := range p.p {
		close(w.job)
	}
	clear(p.p)
	p.p = nil
}

func (p *goSubPool) gc() {
	const maxBatchSize = 256
	var closeWait [maxBatchSize]*goWorker
	var needEmit = -1

	for {
		if needEmit == 0 {
			return
		}

		p.m.Lock()
		if needEmit == -1 {
			// These workers have been sit idle since latest gc.
			needEmit = p.minIdleSinceLatestGC
		}
		if needEmit == 0 {
			p.minIdleSinceLatestGC = len(p.p)
			p.m.Unlock()
			return
		}
		batchSize := min(maxBatchSize, needEmit, len(p.p))
		emitSlice := p.p[len(p.p)-batchSize : len(p.p)]
		copy(closeWait[:], emitSlice)
		clear(emitSlice)
		p.p = p.p[:len(p.p)-batchSize]
		needEmit -= batchSize

		if needEmit == 0 { // gc is done
			if c := cap(p.p); c > 64 && c>>2 > len(p.p) { // len is < 25% of the cap
				p.p = append(make([]*goWorker, 0, c>>1), p.p...) // shrink the slice to half of the cap
			}
			p.minIdleSinceLatestGC = len(p.p)
		}
		p.m.Unlock()

		for i := 0; i < batchSize; i++ {
			close(closeWait[i].job)
		}
	}
}

func (p *goSubPool) putIdle(w *goWorker) (ok bool) {
	p.m.Lock()
	if p.closed {
		p.m.Unlock()
		return false
	}
	p.p = append(p.p, w)
	p.m.Unlock()
	return true
}

type goWorker struct {
	p   *goSubPool
	job chan func()
}

func (w *goWorker) jobLoop(fn func()) {
	fn()
	ok := w.p.putIdle(w)
	if !ok {
		return
	}
	for fn := range w.job {
		fn()
		ok = w.p.putIdle(w)
		if !ok {
			return
		}
	}
}

func (p *goSubPool) newWorker(fn func()) {
	w := &goWorker{
		p:   p,
		job: make(chan func(), 1),
	}
	go w.jobLoop(fn)
}
