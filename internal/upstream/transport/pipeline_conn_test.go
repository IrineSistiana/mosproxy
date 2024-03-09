package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/stretchr/testify/require"
)

func Test_pipelineConn(t *testing.T) {
	t.Run("exchange", func(t *testing.T) {
		r := require.New(t)

		transport := NewPipelineTransport(PipelineOpts{})
		clientConn, _ := newEchoConn()
		pipelineConn := newPipelineConn(clientConn, transport)
		resp, err := pipelineConn.exchange(context.Background(), newTestMsg(666, "test.test"))
		r.NoError(err)
		r.EqualValues(666, resp.ID)
		respName, err := dnsmsg.ToReadable(resp.Questions[0].Name)
		r.NoError(err)
		r.True(string(respName) == "test.test")
	})

	t.Run("server_connection_closed", func(t *testing.T) {
		r := require.New(t)

		transport := NewPipelineTransport(PipelineOpts{})
		clientConn, serverConn := newEchoConn()
		pipelineConn := newPipelineConn(clientConn, transport)
		serverConn.Close()
		select {
		case <-time.After(time.Second):
			r.FailNow("pipeline connection should be closed when peer closed the connection")
		case <-pipelineConn.ctx.Done():
		}
	})

	t.Run("idle_timeout", func(t *testing.T) {
		r := require.New(t)

		transport := NewPipelineTransport(PipelineOpts{IdleTimeout: time.Millisecond * 100})
		clientConn, _ := net.Pipe()
		pipelineConn := newPipelineConn(clientConn, transport)
		select {
		case <-time.After(time.Second):
			r.FailNow("pipeline connection should be closed after idle timeout")
		case <-pipelineConn.ctx.Done():
		}
	})
}
