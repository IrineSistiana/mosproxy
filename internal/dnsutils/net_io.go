package dnsutils

import (
	"encoding/binary"
	"io"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

// Note: ReadMsgFromTCP read c twice (header length and then body).
// Buffered reader is recommended.
func ReadMsgFromTCP(c io.Reader) (*dnsmsg.Msg, int, error) {
	hdrBuf := pool.GetBuf(2)
	defer pool.ReleaseBuf(hdrBuf)
	var n int
	nr, err := io.ReadFull(c, hdrBuf.B())
	n += nr
	if err != nil {
		return nil, n, err
	}

	length := binary.BigEndian.Uint16(hdrBuf.B())
	msgBuf := pool.GetBuf(int(length))
	defer pool.ReleaseBuf(msgBuf)
	nr, err = io.ReadFull(c, msgBuf.B())
	n += nr
	if err != nil {
		return nil, n, err
	}

	m, err := dnsmsg.UnpackMsg(msgBuf.B())
	return m, n, err
}

func ReadMsgFromUDP(c io.Reader, bufSize int) (*dnsmsg.Msg, int, error) {
	if bufSize < 2048 {
		bufSize = 2048 // Should be enough for 99% cases.
	}
	b := pool.GetBuf(bufSize)
	defer pool.ReleaseBuf(b)
	n, err := c.Read(b.B())
	if err != nil {
		return nil, n, err
	}
	m, err := dnsmsg.UnpackMsg(b.B()[:n])
	return m, n, err
}
