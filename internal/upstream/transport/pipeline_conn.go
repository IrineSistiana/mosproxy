package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/upstream/transport/connpool"
)

var (
	errPipelineConnClosed = errors.New("pipeline connection closed")
	errPipelineConnEoL    = errors.New("pipeline connection eol")
)

// pipelineConn is a low-level pipelining connection for traditional dns protocol, where
// dns frames transport in a single and simple connection. (e.g. udp, tcp, tls)
type pipelineConn struct {
	c net.Conn
	t *PipelineTransport

	ctx         context.Context
	cancelCause context.CancelCauseFunc

	m        sync.RWMutex
	closed   bool
	qid      int
	reserved int
	queue    map[uint32]chan *dnsmsg.Msg // uint32 for faster map
}

func newPipelineConn(c net.Conn, t *PipelineTransport) *pipelineConn {
	ctx, cancel := context.WithCancelCause(context.Background())
	pc := &pipelineConn{
		c:           c,
		t:           t,
		ctx:         ctx,
		cancelCause: cancel,
		queue:       make(map[uint32]chan *dnsmsg.Msg),
	}
	pc.startLoops()
	debugLogTransportConnOpen(c, t.logger)
	return pc
}

func (c *pipelineConn) startLoops() {
	go c.readLoop()
}

// exchange writes payload to connection waits for its reply.
func (c *pipelineConn) exchange(ctx context.Context, m []byte) (*dnsmsg.Msg, error) {
	respChan := make(chan *dnsmsg.Msg, 1)
	qid, err := c.addQueueC(respChan)
	if err != nil {
		return nil, err
	}
	defer c.deleteQueueC(qid)

	err = c.write(m, qid)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	case r := <-respChan:
		r.Header.ID = binary.BigEndian.Uint16(m)
		return r, nil
	}
}

func (c *pipelineConn) readLoop() {
	isTCP := c.t.opts.IsTCP
	idleTimeout := c.t.connIdleTimeout()
	var br *bufio.Reader // nil if c is not tcp
	if isTCP {
		br = pool.NewBR1K(c.c)
		defer pool.ReleaseBR1K(br)
	}

	for {
		c.c.SetReadDeadline(time.Now().Add(idleTimeout))
		var (
			r   *dnsmsg.Msg
			err error
		)
		if isTCP {
			r, _, err = dnsutils.ReadMsgFromTCP(br)
		} else {
			var n int
			r, n, err = dnsutils.ReadMsgFromUDP(c.c, 4096) // TODO: make udp read buf size configurable?
			if err != nil {
				if isUdpMsgSizeErr(err) { // windows.WSAEMSGSIZE
					c.t.logger.Warn().
						Err(err).
						Msg("failed to read udp resp due to small buf size")
					continue
				}
				if n > 0 { // Has some data but the msg is invalid. Read buffer to small?
					c.t.logger.Warn().
						Err(err).
						Msg("failed to read udp resp, invalid msg or insufficient read buffer")
					continue
				}
			}
		}

		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				err = ErrIdleTimeOut
			}
			c.closeWithErr(fmt.Errorf("read err, %w", err)) // abort this connection.
			return
		}

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

func (c *pipelineConn) write(m []byte, qid uint16) (err error) {
	isTCP := c.t.opts.IsTCP
	if isTCP {
		b, err := copyMsgWithLenHdr(m)
		setQid(b, 2, qid)
		if err != nil {
			return err
		}
		_, err = c.c.Write(b)
		pool.ReleaseBuf(b)
		return err
	}

	b := pool.GetBuf(len(m))
	bb := b
	copy(bb, m)
	setQid(bb, 0, qid)

	_, err = c.c.Write(bb)
	pool.ReleaseBuf(b)
	if err != nil {
		if isUdpMsgSizeErr(err) {
			c.t.logger.Warn().Err(err).Msg("failed to write req due to udp size limit")
		} else {
			c.closeWithErr(fmt.Errorf("write err, %w", err))
		}
		return err
	}
	return nil
}

func (c *pipelineConn) Close() error {
	c.closeWithErr(nil)
	return nil
}

func (c *pipelineConn) Status() (s connpool.ConnStatus) {
	maxConcurrent := c.t.maxConcurrentQuery()
	c.m.RLock()
	defer c.m.RUnlock()

	s.Closed = c.closed

	availableConcurrent := 0
	if maxConcurrent > len(c.queue)+c.reserved {
		availableConcurrent = maxConcurrent - len(c.queue) - c.reserved
	}
	availableQid := 0
	if 65535 > c.qid {
		availableQid = 65535 - c.qid
	}
	s.AvailableReq = uint64(min(availableConcurrent, availableQid))
	s.CurrentReq = uint64(len(c.queue))
	return s
}

func (c *pipelineConn) ReserveReq(l uint64) {
	c.m.Lock()
	defer c.m.Unlock()
	c.reserved += int(l)
}

// closeWithErr closes this pipelineConn. The error will be sent
// to the waiting Exchange calls.
// Subsequent calls are noop.
func (c *pipelineConn) closeWithErr(err error) {
	if err == nil {
		err = errPipelineConnClosed
	}

	c.m.Lock()
	if c.closed {
		c.m.Unlock()
		return
	}
	c.closed = true
	c.m.Unlock()

	c.cancelCause(err)
	c.c.Close()
	debugLogTransportConnClosed(c.c, c.t.logger, err)
}

func (c *pipelineConn) getQueueC(qid uint16) chan<- *dnsmsg.Msg {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.queue[uint32(qid)]
}

// Add resp chan to queue. Returns assigned qid, or false if connection is EOL.
func (c *pipelineConn) addQueueC(respChan chan *dnsmsg.Msg) (uint16, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.qid > 65535 {
		return 0, errPipelineConnEoL
	}
	qid := uint16(c.qid)
	c.qid++
	if c.reserved > 0 {
		c.reserved--
	}
	c.queue[uint32(qid)] = respChan
	return qid, nil
}

func (c *pipelineConn) deleteQueueC(qid uint16) {
	c.m.Lock()
	delete(c.queue, uint32(qid))
	eol := c.qid > 65535 && len(c.queue) == 0

	c.m.Unlock()
	if eol {
		c.closeWithErr(errPipelineConnEoL)
	}
}
