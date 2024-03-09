package connpool

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dialTimeout    = time.Second * 10
	maxSearchSteps = 16
)

var (
	ErrPoolClosed           = errors.New("pool closed")
	ErrResourceNotAvailable = errors.New("resource not available")
)

type PoolConn interface {
	io.Closer
	Status() ConnStatus
	ReserveReq(l uint64)
}

type ConnStatus struct {
	Closed       bool
	AvailableReq uint64
	CurrentReq   uint64
}

// Pool is a conn pool for client
type Pool struct {
	opts Opts

	m              sync.Mutex
	closed         bool
	dialingCalls   map[*dialingCall]struct{}
	lastDialCall   *dialingCall
	conns          map[PoolConn]struct{}
	lastPickedConn PoolConn
}

type Opts struct {
	Dial func(ctx context.Context) (PoolConn, error)

	// Max number of connections (include dialing connections) this pool
	// can have. Default is no limit.
	MaxConn int

	// Maximum requests that can be queued up for a dialing connections.
	// Default is 1.
	MaxDialingConnReq uint64
}

func NewPool(opts Opts) *Pool {
	return &Pool{
		opts:         opts,
		dialingCalls: make(map[*dialingCall]struct{}),
		conns:        make(map[PoolConn]struct{}),
	}
}

func (p *Pool) ActiveConnections() int {
	p.m.Lock()
	defer p.m.Unlock()
	if p.closed {
		return 0
	}
	return len(p.dialingCalls) + len(p.conns)
}

func (p *Pool) GetConn() (_ PoolConn, newConn bool, err error) {
	waitDialCall := func(dc *dialingCall) (conn PoolConn, newConn bool, err error) {
		conn, err = dc.waitConn()
		return conn, true, err
	}

	p.m.Lock()
	if p.closed {
		p.m.Unlock()
		return nil, false, ErrPoolClosed
	}

	// Try to use last picked conn.
	if conn := p.lastPickedConn; conn != nil {
		status := conn.Status()
		if canTakeReq(status) {
			conn.ReserveReq(1)
			p.m.Unlock()
			return conn, false, nil
		}
		p.lastPickedConn = nil
	}

	// Try pick a conn from pool.
	conn := p.pickupConnLocked()
	if conn != nil {
		p.lastPickedConn = conn
		conn.ReserveReq(1)
		p.m.Unlock()
		return conn, false, nil
	}

	// Try to queue the request to the latest dial call.
	if dc := p.lastDialCall; dc != nil {
		if dc.availableReq > 0 {
			dc.availableReq--
			p.m.Unlock()
			return waitDialCall(dc)
		}
		p.lastDialCall = nil
	}

	// Dial new connection.
	maxConn := p.opts.MaxConn
	if maxConn <= 0 || len(p.dialingCalls)+len(p.conns) < maxConn {
		dc := p.newDialCall()
		dc.availableReq-- // new call start with 1, will not underflow there.
		p.lastDialCall = dc
		p.dialingCalls[dc] = struct{}{}
		p.m.Unlock()

		go dc.dial()
		return waitDialCall(dc)
	}

	// No conn available and can't dial new connection.
	p.m.Unlock()
	return nil, false, ErrResourceNotAvailable
}

func (p *Pool) MarkDead(conn PoolConn) {
	p.m.Lock()
	delete(p.conns, conn)
	p.m.Unlock()
	conn.Close()
}

func (p *Pool) pickupConnLocked() PoolConn {
	searchSteps := 0
	var pickedConn PoolConn
	var lowestReq uint64
	for conn := range p.conns {
		status := conn.Status()
		if status.Closed {
			delete(p.conns, conn)
			continue
		}

		if searchSteps > maxSearchSteps {
			break
		}
		searchSteps++

		if status.AvailableReq == 0 {
			continue
		}

		if lowestReq == 0 || status.CurrentReq < lowestReq {
			pickedConn = conn
			lowestReq = status.CurrentReq
		}
	}
	return pickedConn
}

// Close the pool and all connections.
// Always returns nil.
func (p *Pool) Close() error {
	p.m.Lock()
	defer p.m.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	for dc := range p.dialingCalls {
		dc.cancelDial(ErrPoolClosed)
	}
	for conn := range p.conns {
		conn.Close()
	}
	return nil
}

type dialingCall struct {
	p      *Pool
	ctx    context.Context
	cancel context.CancelFunc

	// protected by p.m
	availableReq uint64

	delivered     atomic.Bool
	deliverNotify chan struct{}
	conn          PoolConn
	err           error
}

func (p *Pool) maxDialingConnReq() uint64 {
	maxQueue := p.opts.MaxDialingConnReq
	if maxQueue == 0 {
		maxQueue = 1
	}
	return maxQueue
}

func (p *Pool) newDialCall() *dialingCall {
	maxQueue := p.opts.MaxDialingConnReq
	if maxQueue == 0 {
		maxQueue = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	ls := &dialingCall{
		p:             p,
		ctx:           ctx,
		cancel:        cancel,
		availableReq:  maxQueue,
		deliverNotify: make(chan struct{}),
	}
	return ls
}

func (dc *dialingCall) dial() {
	p := dc.p
	defer dc.cancel()
	c, err := p.opts.Dial(dc.ctx)
	delivered := dc.tryDeliverConn(c, err)
	if c != nil && !delivered {
		c.Close()
	}

	p.m.Lock()
	if p.lastDialCall == dc {
		p.lastDialCall = nil
	}
	delete(p.dialingCalls, dc)
	if conn := dc.conn; conn != nil {
		conn.ReserveReq(p.maxDialingConnReq() - dc.availableReq)
		p.conns[conn] = struct{}{}
	}
	p.m.Unlock()
}

func (dc *dialingCall) tryDeliverConn(c PoolConn, err error) (delivered bool) {
	if (c == nil && err == nil) || (c != nil && err != nil) {
		panic("invalid tryDeliverConn call with nil args")
	}

	if !dc.delivered.CompareAndSwap(false, true) {
		return false
	}

	dc.conn = c
	dc.err = err
	close(dc.deliverNotify)
	return true
}

func (dc *dialingCall) waitConn() (PoolConn, error) {
	<-dc.deliverNotify
	return dc.conn, dc.err
}

var (
	errDialCanceled = errors.New("dial canceled")
)

func (dc *dialingCall) cancelDial(err error) {
	if err == nil {
		err = errDialCanceled
	}

	if !dc.delivered.CompareAndSwap(false, true) {
		return
	}

	dc.cancel()
	dc.err = err
	close(dc.deliverNotify)
}
