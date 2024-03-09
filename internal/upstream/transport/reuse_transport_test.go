package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ReuseConnTransport(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	rt := NewReuseConnTransport(ReuseConnOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			c, _ := newEchoConn()
			return c, nil
		},
	})
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id := uint16(666)
	name := "test.test."
	req := newTestMsg(id, name)

	wg := new(sync.WaitGroup)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if t.Failed() {
				return
			}
			resp, err := rt.ExchangeContext(ctx, req)
			a.NoError(err)
			a.EqualValues(666, resp.ID)
			respName, err := dnsmsg.ToReadable(resp.Questions[0].Name)
			a.NoError(err)
			a.True(string(respName) == "test.test")
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	rt.m.Lock()
	connNum := len(rt.conns)
	idledConnNum := len(rt.idleConns)
	rt.m.Unlock()

	r.True(connNum == idledConnNum, "there should be no active conn")
	r.True(idledConnNum > 0, "some conns should be idled")
}

func Test_ReuseConnTransport_DialErr(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dialErr := errors.New("dial err")
	rt := NewReuseConnTransport(ReuseConnOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			return nil, dialErr
		},
	})
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := newTestMsg(0, ".")

	wg := new(sync.WaitGroup)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if t.Failed() {
				return
			}
			_, err := rt.ExchangeContext(ctx, req)
			a.ErrorIs(err, dialErr)
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	rt.m.Lock()
	connNum := len(rt.conns)
	idledConnNum := len(rt.idleConns)
	rt.m.Unlock()

	r.True(connNum == 0)
	r.True(idledConnNum == 0)
}
