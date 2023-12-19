package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/dnsutils"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dummyEchoNetConn struct {
	net.Conn

	opt dummyEchoNetConnOpts

	closeOnce   sync.Once
	closeNotify chan struct{}
}

type dummyEchoNetConnOpts struct {
	rErrProb float64
	rLatency time.Duration
	wErrProb float64
}

func newDummyEchoNetConn(opt dummyEchoNetConnOpts) net.Conn {
	c1, c2 := net.Pipe()
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		defer c1.Close()
		defer c2.Close()
		for {
			m, _, readErr := dnsutils.ReadMsgFromTCP(c2)
			c2.SetDeadline(time.Now().Add(time.Second))
			if m != nil {
				go func() {
					defer dnsmsg.ReleaseMsg(m)
					m.Header.Response = true
					if opt.rLatency > 0 {
						t := time.NewTimer(opt.rLatency)
						defer t.Stop()
						select {
						case <-t.C:
						case <-ctx.Done():
							return
						}
					}
					latency := time.Millisecond * time.Duration(rand.Intn(20))
					time.Sleep(latency)
					buf := pool.GetBuf(m.Len())
					defer pool.ReleaseBuf(buf)
					bs := buf.B()
					n, err := m.Pack(bs[2:], false, 0)
					if n > 65535 {
						log.Printf("msg is too big")
					}
					if err != nil {
						log.Printf("failed to pack msg, %v", err)
					}
					binary.BigEndian.PutUint16(bs, uint16(n))
					_, err = c2.Write(bs)
					if err != nil {
						log.Printf("failed to write msg, %v", err)
					}
				}()
			}
			if readErr != nil {
				return
			}
		}
	}()
	return &dummyEchoNetConn{
		Conn:        c1,
		opt:         opt,
		closeNotify: make(chan struct{}),
	}
}

func probTrue(p float64) bool {
	return rand.Float64() < p
}

func (d *dummyEchoNetConn) Read(p []byte) (n int, err error) {
	if probTrue(d.opt.rErrProb) {
		return 0, errors.New("read err")
	}
	return d.Conn.Read(p)
}

func (d *dummyEchoNetConn) Write(p []byte) (n int, err error) {
	if probTrue(d.opt.wErrProb) {
		return 0, errors.New("write err")
	}
	return d.Conn.Write(p)
}

func (d *dummyEchoNetConn) Close() error {
	d.closeOnce.Do(func() {
		close(d.closeNotify)
	})
	return d.Conn.Close()
}

func Test_pipelineConn_exchange(t *testing.T) {
	idleTimeout := time.Millisecond * 100

	tests := []struct {
		name       string
		rErrProb   float64
		rLatency   time.Duration
		wErrProb   float64
		connClosed bool // connection is closed before calling exchange()
		wantMsg    bool
		wantErr    bool
	}{
		{
			name:     "normal",
			rErrProb: 0,
			rLatency: 0,
			wErrProb: 0,
			wantMsg:  true, wantErr: false,
		},
		{
			name:     "write err",
			rErrProb: 0,
			rLatency: 0,
			wErrProb: 1,
			wantMsg:  false, wantErr: true,
		},
		{
			name:     "read err",
			rErrProb: 1,
			rLatency: 0,
			wErrProb: 0,
			wantMsg:  false, wantErr: true,
		},
		{
			name:     "read timeout",
			rErrProb: 0,
			rLatency: idleTimeout * 3,
			wErrProb: 0,
			wantMsg:  false, wantErr: true,
		},
		{
			name:       "connection closed",
			rErrProb:   0,
			rLatency:   0,
			wErrProb:   0,
			connClosed: true,
			wantMsg:    false, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			pt := NewPipelineTransport(PipelineOpts{
				DialContext: func(ctx context.Context) (net.Conn, error) {
					opt := dummyEchoNetConnOpts{
						rErrProb: tt.rErrProb,
						rLatency: tt.rLatency,
						wErrProb: tt.wErrProb,
					}
					return newDummyEchoNetConn(opt), nil
				},
				IdleTimeout: idleTimeout,
				IsTCP:       true,
			})

			call, pc, qid, closed := pt.reserveConn()
			r.NotNil(call)
			r.Nil(pc)
			r.False(closed)
			<-call.done
			dc := call.c
			r.NotNil(dc)

			if tt.connClosed {
				dc.closeWithErr(errors.New("closed"), false)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion("test.", dns.TypeA)
			q.Id = qid
			qWire, err := q.Pack()
			r.NoError(err)
			payload, err := copyMsgWithLenHdr(qWire)
			r.NoError(err)

			respPayload, err := dc.exchange(ctx, nil, payload.B(), qid)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}

			if tt.wantMsg {
				r.NotNil(respPayload)

				// test idle timeout
				time.Sleep(idleTimeout + time.Millisecond*20)
				runtime.Gosched()

				var closed bool
				select {
				case <-dc.closeNotify:
					closed = true
				default:
				}
				r.True(closed, "connection should be closed due to idle timeout")
			} else {
				r.Nil(respPayload)
			}
		})
	}
}

func Test_pipelineConn_exchange_race(t *testing.T) {
	r := require.New(t)
	pt := NewPipelineTransport(PipelineOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			opt := dummyEchoNetConnOpts{
				rErrProb: 0.5,
				rLatency: time.Millisecond * 20,
				wErrProb: 0.5,
			}
			return newDummyEchoNetConn(opt), nil
		},
		IdleTimeout: time.Millisecond * 50,
		IsTCP:       true, // TODO: Test false as well
	})

	wg := new(sync.WaitGroup)
	for j := 0; j < 24; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion("test.", dns.TypeA)
			queryPayload, err := q.Pack()
			r.NoError(err)

			call, pc, qid, closed := pt.reserveConn()
			r.False(closed)
			if call != nil {
				<-call.done
				pc = call.c
				var ok bool
				qid, _, ok = pc.reserveQid()
				r.True(ok)
			}

			_, _ = pc.exchange(ctx, nil, queryPayload, qid)
		}()
	}

	wg.Wait()
}

func Test_pipelineConn_eol(t *testing.T) {
	r := require.New(t)
	pt := NewPipelineTransport(PipelineOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			opt := dummyEchoNetConnOpts{}
			return newDummyEchoNetConn(opt), nil
		},
		IdleTimeout: time.Hour,
	})
	pt._testConnMaxServedQueries = 1

	call, pc, _, closed := pt.reserveConn()
	r.False(closed)
	if call != nil {
		<-call.done
		pc = call.c
		var ok bool
		_, _, ok = pc.reserveQid()
		r.True(ok)
	}
	lastCall := pc.releaseQid()
	r.True(lastCall)
	<-pc.closeNotify
	r.ErrorIs(pc.closeErr, ErrPipelineConnEoL)
}
