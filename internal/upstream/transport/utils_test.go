package transport

import (
	"fmt"
	"io"
	"net"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

func newEchoConn() (c, s net.Conn) {
	c, s = net.Pipe()
	go func() {
		io.Copy(s, s)
	}()
	return
}

func newTestMsg(id uint16, name string) *dnsmsg.Msg {
	m := dnsmsg.NewMsg()
	m.ID = id
	q := dnsmsg.NewQuestion()
	err := q.Name.Parse(name)
	if err != nil {
		panic(fmt.Sprintf("failed to pack name, %s", err))
	}
	m.Questions = append(m.Questions, q)
	return m
}
