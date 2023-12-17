package transport

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func Test_ReuseConnTransport(t *testing.T) {
	const idleTimeout = time.Second * 5
	r := require.New(t)

	po := ReuseConnOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			return newDummyEchoNetConn(dummyEchoNetConnOpts{}), nil
		},
		IdleTimeout: idleTimeout,
	}
	rt := NewReuseConnTransport(po)
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeA)
	queryPayload, err := q.Pack()
	r.NoError(err)
	concurrentQueryNum := 10
	for l := 0; l < 4; l++ {
		wg := new(sync.WaitGroup)
		for i := 0; i < concurrentQueryNum; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := rt.ExchangeContext(ctx, queryPayload)
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if t.Failed() {
			return
		}
	}

	rt.m.Lock()
	connNum := len(rt.conns)
	idledConnNum := len(rt.idleConns)
	rt.m.Unlock()

	r.Equal(0, connNum-idledConnNum, "there should be no active conn")
	r.Equal(concurrentQueryNum, connNum)
	r.Equal(concurrentQueryNum, idledConnNum, "all conn should be in idle status")
}

func Test_ReuseConnTransport_Read_err_and_close(t *testing.T) {
	const idleTimeout = time.Second * 5
	r := require.New(t)

	po := ReuseConnOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			opt := dummyEchoNetConnOpts{
				rErrProb: 1,
			}
			return newDummyEchoNetConn(opt), nil // 100% read err
		},
		IdleTimeout: idleTimeout,
	}
	rt := NewReuseConnTransport(po)
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeA)
	queryPayload, err := q.Pack()
	r.NoError(err)

	wg := new(sync.WaitGroup)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := rt.ExchangeContext(ctx, queryPayload)
			r.Error(err)
		}()
		if t.Failed() {
			return
		}
	}
	wg.Wait()

	rt.m.Lock()
	connNum := len(rt.conns)
	idledConnNum := len(rt.idleConns)
	rt.m.Unlock()

	r.Equal(0, connNum)
	r.Equal(0, idledConnNum)
}

func Test_ReuseConnTransport_conn_lose_and_close(t *testing.T) {
	r := require.New(t)
	po := ReuseConnOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			opt := dummyEchoNetConnOpts{
				rErrProb: 0,
				rLatency: time.Second,
			}
			return newDummyEchoNetConn(opt), nil // 100% read timeout
		},
	}
	rt := NewReuseConnTransport(po)
	defer rt.Close()
	rt.testWaitRespTimeout = time.Millisecond * 1

	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeA)
	queryPayload, err := q.Pack()
	r.NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()
	_, err = rt.ExchangeContext(ctx, queryPayload) // canceled ctx
	r.Error(err)

	time.Sleep(time.Millisecond * 100)

	rt.m.Lock()
	connNum := len(rt.conns)
	idledConnNum := len(rt.idleConns)
	rt.m.Unlock()

	// connection should be closed and removed
	r.Equal(0, connNum)
	r.Equal(0, idledConnNum)
}
