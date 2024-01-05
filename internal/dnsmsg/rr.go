package dnsmsg

import (
	"encoding/binary"
	"sync"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type Resource struct {
	noCopy
	linkNode

	Name  *pool.Buffer
	Type  Type
	Class Class
	TTL   uint32
	Data  *pool.Buffer
}

// no compression len
func (rr *Resource) len() int {
	l := 0
	l += nameLen(rr.Name)
	l += 10 // type, class, ttl (uint32), length
	dataLen := rr.Data.Len()
	if dataLen > 65535 {
		dataLen = 65535 // let the pack/unpack fail
	}
	l += rr.Data.Len()
	return l
}

func (rr *Resource) Copy() *Resource {
	n := GetRR()
	n.Name = copyBufP(rr.Name)
	n.Type = rr.Type
	n.Class = rr.Class
	n.TTL = rr.TTL
	n.Data = copyBufP(rr.Data)
	return n
}

func unpackRawResource(msg []byte, off int) (*Resource, int, error) {
	name, off, err := unpackName(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("name", err)
	}
	typ, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("type", err)
	}
	cls, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("class", err)
	}
	ttl, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("ttl", err)
	}
	dataLen, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("length", err)
	}
	dataBound := off + int(dataLen)
	if dataBound > len(msg) {
		return nil, 0, newSectionErr("data_length", ErrSmallBuffer)
	}

	var data *pool.Buffer
	switch typ {
	case uint16(TypeCNAME), uint16(TypePTR), uint16(TypeNS):
		data, off, err = decompressName(msg[:dataBound], off)
		if err != nil {
			return nil, 0, newSectionErr("data_name", err)
		}
	case uint16(TypeMX):
		data, off, err = unpackMX(msg[:dataBound], off)
		if err != nil {
			return nil, 0, newSectionErr("data_mx", err)
		}
	case uint16(TypeSOA):
		data, off, err = unpackSOA(msg[:dataBound], off)
		if err != nil {
			return nil, 0, newSectionErr("data_soa", err)
		}
	default:
		data, off, err = unpackBytesMsg(msg[:dataBound], off, int(dataLen))
		if err != nil {
			return nil, 0, newSectionErr("data_other", err)
		}
	}

	r := GetRR()
	r.Name = name
	r.Type = Type(typ)
	r.Class = Class(cls)
	r.TTL = ttl
	r.Data = data
	return r, off, nil
}

func unpackSOA(msg []byte, off int) (*pool.Buffer, int, error) {
	ns, off, err := decompressName(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("ns", err)
	}
	defer pool.ReleaseBuf(ns)
	mBox, off, err := decompressName(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("mbox", err)
	}
	defer pool.ReleaseBuf(mBox)
	serial, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("serial", err)
	}
	refresh, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("refresh", err)
	}
	retry, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("retry", err)
	}
	expire, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("expire", err)
	}
	minTTL, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("minttl", err)
	}

	b := pool.GetBuf(ns.Len() + mBox.Len() + 20)
	repackOff := 0
	repackOff += copy(b.B(), ns.B())
	repackOff += copy(b.B()[repackOff:], mBox.B())
	for _, v := range [...]uint32{serial, refresh, retry, expire, minTTL} {
		binary.BigEndian.PutUint32(b.B()[repackOff:], v)
		repackOff += 4
	}
	return b, off, nil
}

func unpackMX(msg []byte, off int) (*pool.Buffer, int, error) {
	pref, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("pref", err)
	}
	mx, off, err := decompressName(msg, off)
	if err != nil {
		return nil, 0, newSectionErr("mx", err)
	}
	defer pool.ReleaseBuf(mx)

	b := pool.GetBuf(2 + mx.Len())
	putUint16(b.B()[:2], pref)
	copy(b.B()[2:], mx.B())
	return b, off, nil
}

func (rr *Resource) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := packName(rr.Name, msg, off, compression)
	if err != nil {
		return off, newSectionErr("name", err)
	}
	off, err = packUint16(msg, off, uint16(rr.Type))
	if err != nil {
		return off, newSectionErr("type", err)
	}
	off, err = packUint16(msg, off, uint16(rr.Class))
	if err != nil {
		return off, newSectionErr("class", err)
	}
	off, err = packUint32(msg, off, rr.TTL)
	if err != nil {
		return off, newSectionErr("ttl", err)
	}
	rrLen := rr.Data.Len()
	if rrLen > 65535 {
		return off, errResTooLong
	}
	off, err = packUint16(msg, off, uint16(rrLen))
	if err != nil {
		return off, newSectionErr("length", err)
	}
	off, err = packBytes(msg, off, rr.Data.B())
	if err != nil {
		return off, newSectionErr("data", err)
	}
	return off, nil
}

var rrPool = sync.Pool{
	New: func() any {
		return new(Resource)
	},
}

func GetRR() *Resource {
	return rrPool.Get().(*Resource)
}

func ReleaseRR(r *Resource) {
	pool.ReleaseBuf(r.Name)
	pool.ReleaseBuf(r.Data)
	*r = Resource{}
	rrPool.Put(r)
}
