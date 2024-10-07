package dnsmsg

import (
	"encoding/binary"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

func copyBuf(b []byte) pool.Buffer {
	c := pool.GetBuf(len(b))
	copy(c, b)
	return c
}

func bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func packByte(b []byte, v byte) []byte {
	return append(b, v)
}

func packNamePtr(b []byte, hi, lo byte) []byte {
	return append(b, hi, lo)
}

func packUint16(b []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(b, v)
}

func packUint32(b []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(b, v)
}

func packBytes(b []byte, v []byte) []byte {
	return append(b, v...)
}

func putUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

func unpackUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func unpackUint16Msg(msg []byte, off int) (uint16, int, error) {
	buf := msg[off:]
	if len(buf) < 2 {
		return 0, 0, ErrSmallBuffer
	}
	return unpackUint16(buf), off + 2, nil
}

func unpackUint32Msg(msg []byte, off int) (uint32, int, error) {
	buf := msg[off:]
	if len(buf) < 4 {
		return 0, 0, ErrSmallBuffer
	}
	return binary.BigEndian.Uint32(buf), off + 4, nil
}

func unpackBytesMsgToBuffer(msg []byte, off int, l int) (pool.Buffer, int, error) {
	buf := msg[off:]
	if len(buf) < l {
		return nil, 0, ErrSmallBuffer
	}
	return copyBuf(buf[:l]), off + l, nil
}

func unpackBytesMsg(msg []byte, off int, dst []byte) (int, error) {
	buf := msg[off:]
	if len(buf) < len(dst) {
		return 0, ErrSmallBuffer
	}
	copy(dst, buf)
	return off + len(dst), nil
}

func asciiToLower(s []byte) {
	for i, c := range s {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
			s[i] = c
		}
	}
}

func isPrintableLabelChar(b uint8) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9') || b == '-'
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func parseDDD[T []byte | string](b T) (byte, bool) {
	const base = 10
	if len(b) != 3 {
		return 0, false
	}
	s := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 30 || c > 39 {
			return 0, false
		}
		n := c - 30
		s *= base
		s += int(n)
	}
	if s > 255 {
		return 0, false
	}
	return byte(s), true
}
