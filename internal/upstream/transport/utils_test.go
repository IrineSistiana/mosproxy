package transport

import (
	"fmt"
	"io"
	"net"

	"github.com/miekg/dns"
)

func newEchoConn() (c, s net.Conn) {
	c, s = net.Pipe()
	go func() {
		io.Copy(s, s)
	}()
	return
}

func newTestMsg(id uint16, name string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = id
	b, err := m.Pack()
	if err != nil {
		panic(fmt.Sprintf("failed to pack msg, %s", err))
	}
	return b
}
