package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"go.uber.org/zap"
)

var (
	ErrTooManyPipeliningQueries = errors.New("too many pipelining queries") // Connection has too many ongoing queries.
	ErrPipelineConnClosed       = errors.New("pipeline connection closed")
	ErrPipelineConnEoL          = errors.New("pipeline connection eol")
)

// pipelineConn is a low-level pipelining connection for traditional dns protocol, where
// dns frames transport in a single and simple connection. (e.g. udp, tcp, tls)
type pipelineConn struct {
	c net.Conn
	t *PipelineTransport

	closeOnce   sync.Once
	closeNotify chan struct{}
	closeErr    error // closeErr is ready (not nil) when closeNotify is closed.

	// for tcp
	tcpWriteQueue chan *pool.Buffer

	readQueueMu sync.RWMutex
	readQueue   map[uint32]chan *dnsmsg.Msg // uint32 has fast path

	// waitingResp indicates connection is waiting a reply from the peer.
	// It can identify c is dead or buggy in some circumstances. e.g. Network is dropped
	// and the sockets were still open because no fin or rst was received.
	waitingResp atomic.Bool

	statusMu   sync.Mutex
	concurrent int
	reqServed  int
	eol        bool
}

func newPipelineConn(c net.Conn, t *PipelineTransport) *pipelineConn {
	pc := &pipelineConn{
		c: c,
		t: t,

		closeNotify: make(chan struct{}),
		readQueue:   make(map[uint32]chan *dnsmsg.Msg),
	}
	if t.connIsTcp {
		pc.tcpWriteQueue = make(chan *pool.Buffer, 8)
	}
	return pc
}

func (c *pipelineConn) startLoops() {
	go c.readLoop()
	if c.t.connIsTcp {
		go c.writeLoopTCP()
	}
}

// exchange writes payload to connection waits for its reply.
func (c *pipelineConn) exchange(ctx context.Context, ppHdr, m []byte, qid uint16) (*dnsmsg.Msg, error) {
	select {
	case <-c.closeNotify:
		return nil, ErrPipelineConnClosed
	default:
	}

	respChan := c.addQueueC(qid)
	defer c.deleteQueueC(qid)

	err := c.write(ctx, ppHdr, m, qid)
	if err != nil {
		return nil, err
	}

	// If a query was sent, server should have a reply (even not for this query) in a short time.
	// This indicates the connection is healthy. Otherwise, this connection might be dead.
	// The Read deadline will be refreshed in readLoop() after every successful read.
	// Note: There has a race condition in this SetReadDeadline() call and the one in
	// readLoop(). It's not a big problem.
	if c.waitingResp.CompareAndSwap(false, true) {
		c.c.SetReadDeadline(time.Now().Add(pipelineWaitingReplyTimeout))
	}

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case r := <-respChan:
		return r, nil
	case <-c.closeNotify:
		return nil, c.closeErr
	}
}

func (c *pipelineConn) readLoop() {
	var br *bufio.Reader // nil if c is not tcp
	if c.t.connIsTcp {
		br = pool.BufReaderPool1K.Get()
		br.Reset(c.c)
		defer pool.BufReaderPool1K.Release(br)
	}

	for {
		c.c.SetReadDeadline(time.Now().Add(c.t.connIdleTimeout))
		var (
			r   *dnsmsg.Msg
			err error
		)
		if c.t.connIsTcp {
			r, _, err = dnsutils.ReadMsgFromTCP(br)
		} else {
			var n int
			r, n, err = dnsutils.ReadMsgFromUDP(c.c, 4096) // TODO: make udp read buf size configurable?
			if err != nil {
				if isUdpMsgSizeErr(err) { // windows.WSAEMSGSIZE
					c.t.logger.Warn(
						"failed to read udp resp due to small buf size",
						zap.Stringer("local", c.c.LocalAddr()),
						zap.Stringer("remote", c.c.RemoteAddr()),
						zap.Error(err),
					)
					continue
				}
				if n > 0 { // Has some data but the msg is invalid. Read buffer to small?
					c.t.logger.Warn(
						"failed to read udp resp, invalid msg or insufficient read buffer",
						zap.Stringer("local", c.c.LocalAddr()),
						zap.Stringer("remote", c.c.RemoteAddr()),
						zap.Error(err),
					)
					continue
				}
			}

		}

		if err != nil {
			c.closeWithErr(fmt.Errorf("read err, %w", err), false) // abort this connection.
			return
		}
		c.waitingResp.Store(false)

		resChan := c.getQueueC(r.Header.ID)
		if resChan != nil {
			select {
			case resChan <- r: // resChan has buffer
			default:
				dnsmsg.ReleaseMsg(r)
			}
		} else {
			dnsmsg.ReleaseMsg(r)
		}
	}
}

func (c *pipelineConn) write(ctx context.Context, ppHdr, m []byte, qid uint16) (err error) {
	var b *pool.Buffer
	if c.t.connIsTcp {
		var err error
		b, err = copyMsgWithLenHdr(m)
		setQid(b.B(), 2, qid)
		if err != nil {
			return err
		}

		select {
		case c.tcpWriteQueue <- b:
			return nil
		case <-c.closeNotify:
			pool.ReleaseBuf(b)
			return c.closeErr
		case <-ctx.Done():
			return fmt.Errorf("failed to send payload to write queue, %w", context.Cause(ctx))
		}
	}

	b = pool.GetBuf(len(ppHdr) + len(m))
	bb := b.B()
	off := copy(bb, ppHdr)
	copy(bb[off:], m)
	setQid(bb, off, qid)

	_, err = c.c.Write(bb)
	pool.ReleaseBuf(b)
	if err != nil {
		if isUdpMsgSizeErr(err) {
			c.t.logger.Warn(
				"failed to write req due to udp size limit",
				zap.Stringer("local", c.c.LocalAddr()),
				zap.Stringer("remote", c.c.RemoteAddr()),
				zap.Error(err),
			)
		} else {
			c.closeWithErr(fmt.Errorf("write err, %w", err), false)
		}
		return err
	}
	return nil
}

func (c *pipelineConn) writeLoopTCP() {
	bw := pool.BufWriterPool1K.Get()
	bw.Reset(c.c)
	defer pool.BufWriterPool1K.Release(bw)

	for {
		select {
		case <-c.closeNotify:
			return
		case b := <-c.tcpWriteQueue:
			var err error
			_, err = bw.Write(b.B())
			pool.ReleaseBuf(b)
			if err != nil {
				goto writeErr
			}
		readMore:
			for {
				select {
				case b := <-c.tcpWriteQueue:
					_, err = bw.Write(b.B())
					pool.ReleaseBuf(b)
					if err != nil {
						goto writeErr
					}
				default:
					break readMore
				}
			}
			err = bw.Flush()
			if err != nil {
				goto writeErr
			}
			continue

		writeErr:
			c.closeWithErr(fmt.Errorf("write err, %w", err), false)
			return
		}
	}
}

// closeWithErr closes this pipelineConn. The error will be sent
// to the waiting Exchange calls.
// Subsequent calls are noop.
func (c *pipelineConn) closeWithErr(err error, byTransport bool) {
	c.closeOnce.Do(func() {
		if !byTransport {
			c.t.m.Lock()
			delete(c.t.conns, c)
			delete(c.t.eols, c)
			c.t.m.Unlock()
		}

		c.closeErr = err
		close(c.closeNotify)
		c.c.Close()
		debugLogTransportConnClosed(c.c, c.t.logger, err)
	})
}

func (c *pipelineConn) getQueueC(qid uint16) chan<- *dnsmsg.Msg {
	c.readQueueMu.RLock()
	defer c.readQueueMu.RUnlock()
	return c.readQueue[uint32(qid)]
}

// addQueueC assigns a qid to the queue.
// Caller must call deleteQueueC to release the qid in queue.
func (c *pipelineConn) addQueueC(qid uint16) (resChan chan *dnsmsg.Msg) {
	resChan = make(chan *dnsmsg.Msg, 1)
	c.readQueueMu.Lock()
	c.readQueue[uint32(qid)] = resChan
	c.readQueueMu.Unlock()
	return resChan
}

func (c *pipelineConn) deleteQueueC(qid uint16) {
	c.readQueueMu.Lock()
	delete(c.readQueue, uint32(qid))
	c.readQueueMu.Unlock()
}

// call releaseQid() after exchange()
func (c *pipelineConn) reserveQid() (qid uint16, eol, ok bool) {
	limit := c.t.connMaxConcurrentQueries
	c.statusMu.Lock()
	defer c.statusMu.Unlock()

	if c.eol {
		return 0, true, false
	}

	if c.concurrent >= limit {
		return 0, false, false
	}
	c.concurrent++
	c.reqServed++

	var maxServed uint16 = 65535
	if c.t._testConnMaxServedQueries > 0 {
		maxServed = c.t._testConnMaxServedQueries
	}
	if c.reqServed >= int(maxServed) {
		c.eol = true
		eol = true
	}
	return uint16(c.reqServed), eol, true
}

func (c *pipelineConn) releaseQid() (lastCall bool) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.concurrent--
	if c.eol && c.concurrent == 0 {
		lastCall = true
		c.closeWithErr(ErrPipelineConnEoL, false)
	}
	return lastCall
}
