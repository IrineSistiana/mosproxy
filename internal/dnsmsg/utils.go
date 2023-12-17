package dnsmsg

import (
	"encoding/binary"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func nameLen(b *pool.Buffer) int { // let the pack/unpack fail
	l := b.Len()
	switch {
	case l <= 1: // 0: invalid, return minimum, 1: assuming is root
		return 1
	case l > 255: // invalid
		return 255
	default:
		return l + 1
	}
}

func copyBuf(b []byte) *pool.Buffer {
	c := pool.GetBuf(len(b))
	copy(c.B(), b)
	return c
}

func copyBufP(b *pool.Buffer) *pool.Buffer {
	c := pool.GetBuf(b.Len())
	copy(c.B(), b.B())
	return c
}

func bytes2StrUnsafe(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func packByte(b []byte, off int, v byte) (int, error) {
	if off+1 <= len(b) {
		b[off] = v
		off += 1
		return off, nil
	}
	return off, ErrSmallBuffer
}

func packNamePtr(b []byte, off int, v [2]byte) (int, error) {
	if off+2 <= len(b) {
		copy(b[off:], v[:])
		off += 2
		return off, nil
	}
	return off, ErrSmallBuffer
}

func packUint16(b []byte, off int, v uint16) (int, error) {
	if off+2 <= len(b) {
		binary.BigEndian.PutUint16(b[off:], v)
		off += 2
		return off, nil
	}
	return off, ErrSmallBuffer
}

func packUint32(b []byte, off int, v uint32) (int, error) {
	if off+4 <= len(b) {
		binary.BigEndian.PutUint32(b[off:], v)
		off += 4
		return off, nil
	}
	return off, ErrSmallBuffer
}

func packBytes(b []byte, off int, v []byte) (int, error) {
	if off+len(v) <= len(b) {
		copy(b[off:], v)
		off += len(v)
		return off, nil
	}
	return off, ErrSmallBuffer
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

func unpackBytesMsg(msg []byte, off int, l int) (*pool.Buffer, int, error) {
	buf := msg[off:]
	if len(buf) < l {
		return nil, 0, ErrSmallBuffer
	}
	return copyBuf(buf[:l]), off + l, nil
}
