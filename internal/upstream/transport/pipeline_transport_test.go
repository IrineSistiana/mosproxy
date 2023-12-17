package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func (t *PipelineTransport) _testCloseAllPipelineSubConn() {
	t.m.Lock()
	defer t.m.Unlock()
	for conn := range t.conns {
		conn.c.Close()
	}
}

func Test_PipelineTransport(t *testing.T) {
	r := require.New(t)
	po := PipelineOpts{
		DialContext: func(ctx context.Context) (net.Conn, error) {
			opt := dummyEchoNetConnOpts{}
			return newDummyEchoNetConn(opt), nil
		},
		MaxConcurrentQuery: 10,
		IsTCP:              true,
	}
	pt := NewPipelineTransport(po)
	defer pt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeA)
	queryPayload, err := q.Pack()
	r.NoError(err)

	// A connection should be created.
	_, err = pt.ExchangeContext(ctx, queryPayload)
	r.NoError(err)

	pt.m.Lock()
	connNum := len(pt.conns)
	var pc *pipelineConn
	for pc = range pt.conns {
		break
	}
	dialCallNum := len(pt.dialingCalls)
	pt.m.Unlock()

	r.Equal(1, connNum)
	r.Equal(0, dialCallNum)

	pt._testCloseAllPipelineSubConn()
	<-pc.closeNotify

	// When pipeline conn exited, it should delete itself from the map.
	pt.m.Lock()
	connNum = len(pt.conns)
	dialCallNum = len(pt.dialingCalls)
	pt.m.Unlock()
	r.Equal(0, connNum)
	r.Equal(0, dialCallNum)
}
