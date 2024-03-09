package dnsmsg

import (
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type Resource interface {
	Hdr() *ResourceHdr
	packLen() int
	pack(msg []byte, off int, compression map[string]uint16) (int, error)
	unpack(msg []byte, off int, hdr ResourceHdr) (int, error)
}

type ResourceHdr struct {
	Name   Name
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16 // When unpacking is field is ignored.
}

func (h *ResourceHdr) packLen() int {
	return h.Name.PackLen() + 10 // type, class, ttl (uint32), length
}

func (h *ResourceHdr) unpack(msg []byte, off int) (int, error) {
	var err error
	h.Name, off, err = unpackName(msg, off)
	if err != nil {
		return 0, newSectionErr("name", err)
	}
	typ, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("type", err)
	}
	h.Type = Type(typ)
	cls, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("class", err)
	}
	h.Class = Class(cls)
	ttl, off, err := unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("ttl", err)
	}
	h.TTL = ttl
	dataLen, off, err := unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("length", err)
	}
	h.Length = dataLen
	return off, err
}

func (h *ResourceHdr) pack(msg []byte, off int, compression map[string]uint16, dataLen uint16) (int, error) {
	off, err := h.Name.pack(msg, off, compression)
	if err != nil {
		return off, newSectionErr("name", err)
	}
	off, err = packUint16(msg, off, uint16(h.Type))
	if err != nil {
		return off, newSectionErr("type", err)
	}
	off, err = packUint16(msg, off, uint16(h.Class))
	if err != nil {
		return off, newSectionErr("class", err)
	}
	off, err = packUint32(msg, off, h.TTL)
	if err != nil {
		return off, newSectionErr("ttl", err)
	}

	// h.Length may be invalid in most packing calls.
	off, err = packUint16(msg, off, dataLen)
	if err != nil {
		return off, newSectionErr("length", err)
	}
	return off, nil
}

type A struct {
	ResourceHdr
	A [4]byte
}

var _ Resource = (*A)(nil)

func (r *A) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *A) packLen() int {
	return r.ResourceHdr.packLen() + 4
}

func (r *A) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 4)
	if err != nil {
		return off, err
	}
	off, err = packBytes(msg, off, r.A[:])
	if err != nil {
		return off, newSectionErr("a", err)
	}
	return off, nil
}

func (r *A) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	if r.ResourceHdr.Length != 4 {
		return off, errInvalidResourceBodyLen
	}
	return unpackBytesMsg(msg, off, r.A[:])
}

type AAAA struct {
	ResourceHdr
	AAAA [16]byte
}

var _ Resource = (*AAAA)(nil)

func (r *AAAA) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *AAAA) packLen() int {
	return r.ResourceHdr.packLen() + 16
}

func (r *AAAA) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 16)
	if err != nil {
		return off, err
	}
	off, err = packBytes(msg, off, r.AAAA[:])
	if err != nil {
		return off, newSectionErr("aaaa", err)
	}
	return off, nil
}

func (r *AAAA) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	if r.ResourceHdr.Length != 16 {
		return off, errInvalidResourceBodyLen
	}
	return unpackBytesMsg(msg, off, r.AAAA[:])
}

// CNAME, NS, PTR
type NAMEResource struct {
	ResourceHdr
	NameData Name
}

var _ Resource = (*NAMEResource)(nil)

func (r *NAMEResource) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *NAMEResource) packLen() int {
	return r.ResourceHdr.packLen() + r.NameData.PackLen()
}

func (r *NAMEResource) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 0)
	if err != nil {
		return off, err
	}
	dataLenPlaceholder := msg[off-2 : off]

	dataStartOff := off
	off, err = r.NameData.pack(msg, off, compression)
	if err != nil {
		return off, newSectionErr("data", err)
	}
	putUint16(dataLenPlaceholder, uint16(off)-uint16(dataStartOff))
	return off, nil
}

func (r *NAMEResource) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	oldOff := off
	r.ResourceHdr = hdr
	name, off, err := unpackName(msg, off)
	if err != nil {
		return off, newSectionErr("data", err)
	}
	r.NameData = name

	if off-oldOff != int(r.Length) {
		return off, errInvalidResourceBodyLen
	}
	return off, nil
}

type SOA struct {
	ResourceHdr
	NS      Name
	MBox    Name
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

var _ Resource = (*SOA)(nil)

func (r *SOA) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *SOA) packLen() int {
	return r.ResourceHdr.packLen() + r.NS.PackLen() + r.MBox.PackLen() + 20
}

func (r *SOA) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 0)
	if err != nil {
		return off, err
	}
	dataLenPlaceholder := msg[off-2 : off]

	dataStartOff := off
	off, err = r.NS.pack(msg, off, compression)
	if err != nil {
		return 0, newSectionErr("ns", err)
	}
	off, err = r.MBox.pack(msg, off, compression)
	if err != nil {
		return 0, newSectionErr("mbox", err)
	}
	off, err = packUint32(msg, off, r.Serial)
	if err != nil {
		return 0, newSectionErr("serial", err)
	}
	off, err = packUint32(msg, off, r.Refresh)
	if err != nil {
		return 0, newSectionErr("refresh", err)
	}
	off, err = packUint32(msg, off, r.Retry)
	if err != nil {
		return 0, newSectionErr("retry", err)
	}
	off, err = packUint32(msg, off, r.Expire)
	if err != nil {
		return 0, newSectionErr("expire", err)
	}
	off, err = packUint32(msg, off, r.MinTTL)
	if err != nil {
		return 0, newSectionErr("minttl", err)
	}
	putUint16(dataLenPlaceholder, uint16(off)-uint16(dataStartOff))
	return off, nil
}

func (r *SOA) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	dataStartOff := off

	var err error
	r.NS, off, err = unpackName(msg, off)
	if err != nil {
		return 0, newSectionErr("ns", err)
	}
	r.MBox, off, err = unpackName(msg, off)
	if err != nil {
		return 0, newSectionErr("mbox", err)
	}
	r.Serial, off, err = unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("serial", err)
	}
	r.Refresh, off, err = unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("refresh", err)
	}
	r.Retry, off, err = unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("retry", err)
	}
	r.Expire, off, err = unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("expire", err)
	}
	r.MinTTL, off, err = unpackUint32Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("minttl", err)
	}

	if off-dataStartOff != int(r.Length) {
		return off, errInvalidResourceBodyLen
	}
	return off, nil
}

type MX struct {
	ResourceHdr
	Pref uint16
	MX   Name
}

func (r *MX) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *MX) packLen() int {
	return r.ResourceHdr.packLen() + 2 + r.MX.PackLen()
}

func (r *MX) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 0)
	if err != nil {
		return off, err
	}
	dataLenPlaceholder := msg[off-2 : off]

	dataStartOff := off
	off, err = packUint16(msg, off, r.Pref)
	if err != nil {
		return off, newSectionErr("pref", err)
	}
	off, err = r.MX.pack(msg, off, compression)
	if err != nil {
		return off, newSectionErr("mx", err)
	}
	putUint16(dataLenPlaceholder, uint16(off)-uint16(dataStartOff))
	return off, nil
}

func (r *MX) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	dataStartOff := off

	var err error
	r.Pref, off, err = unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("pref", err)
	}
	r.MX, off, err = unpackName(msg, off)
	if err != nil {
		return 0, newSectionErr("mx", err)
	}
	if off-dataStartOff != int(r.Length) {
		return off, errInvalidResourceBodyLen
	}
	return off, nil
}

type SRV struct {
	ResourceHdr
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Name // Not compressed as per RFC 2782.
}

func (r *SRV) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *SRV) packLen() int {
	return r.ResourceHdr.packLen() + 6 + r.Target.PackLen()
}

func (r *SRV) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := r.ResourceHdr.pack(msg, off, compression, 0)
	if err != nil {
		return off, err
	}
	dataLenPlaceholder := msg[off-2 : off]

	dataStartOff := off
	off, err = packUint16(msg, off, r.Priority)
	if err != nil {
		return off, newSectionErr("priority", err)
	}
	off, err = packUint16(msg, off, r.Weight)
	if err != nil {
		return off, newSectionErr("weight", err)
	}
	off, err = packUint16(msg, off, r.Port)
	if err != nil {
		return off, newSectionErr("port", err)
	}
	off, err = r.Target.pack(msg, off, compression)
	if err != nil {
		return off, newSectionErr("target", err)
	}
	putUint16(dataLenPlaceholder, uint16(off)-uint16(dataStartOff))
	return off, nil
}

func (r *SRV) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	dataStartOff := off

	var err error
	r.Priority, off, err = unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("priority", err)
	}
	r.Weight, off, err = unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("weight", err)
	}
	r.Port, off, err = unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("port", err)
	}
	r.Target, off, err = unpackName(msg, off)
	if err != nil {
		return 0, newSectionErr("target", err)
	}
	if off-dataStartOff != int(r.Length) {
		return off, errInvalidResourceBodyLen
	}
	return off, nil
}

type RawResource struct {
	ResourceHdr
	Data pool.Buffer
}

func (r *RawResource) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (rr *RawResource) packLen() int {
	l := rr.ResourceHdr.packLen()
	dataLen := len(rr.Data)
	if dataLen > 65535 {
		dataLen = 65535 // let the pack/unpack fail
	}
	l += dataLen
	return l
}

func (r *RawResource) unpack(msg []byte, off int, hdr ResourceHdr) (int, error) {
	r.ResourceHdr = hdr
	b, off, err := unpackBytesMsgToBuffer(msg, off, int(hdr.Length))
	if err != nil {
		return off, newSectionErr("data", err)
	}
	r.Data = b
	return off, nil
}

func unpackResource(msg []byte, off int) (Resource, int, error) {
	var hdr ResourceHdr
	off, err := hdr.unpack(msg, off)
	if err != nil {
		return nil, off, err
	}

	var r Resource
	switch hdr.Type {
	case TypeA:
		r = NewA()
	case TypeAAAA:
		r = NewAAAA()
	case TypeMX:
		r = NewMX()
	case TypeCNAME, TypeNS, TypePTR:
		r = NewNAME()
	case TypeSOA:
		r = NewSOA()
	case TypeSRV:
		r = NewSRV()
	default:
		r = NewRaw()
	}

	off, err = r.unpack(msg, off, hdr)
	if err != nil {
		ReleaseResource(r)
		return nil, off, err
	}
	return r, off, nil
}

func (rr *RawResource) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	off, err := rr.Name.pack(msg, off, compression)
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
	rrLen := len(rr.Data)
	if rrLen > 65535 {
		return off, errResTooLong
	}
	off, err = packUint16(msg, off, uint16(rrLen))
	if err != nil {
		return off, newSectionErr("length", err)
	}
	off, err = packBytes(msg, off, rr.Data)
	if err != nil {
		return off, newSectionErr("data", err)
	}
	return off, nil
}
