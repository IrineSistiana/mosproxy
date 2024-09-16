package dnsmsg

import (
	"math"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type Resource interface {
	Hdr() *ResourceHdr
	packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error)
	unpackBody(msg []byte, off int) (int, error)
	Copy() Resource
	packBodyLen(compression map[string]uint16) (int, error)
}

type ResourceHdr struct {
	noCopy
	Name   Name
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16 // ignored when packing
}

func (h *ResourceHdr) reset() {
	h.Name.Reset()
	h.Type = 0
	h.Class = 0
	h.TTL = 0
	h.Length = 0
}

func (h *ResourceHdr) unpack(msg []byte, off int) (int, error) {
	var err error
	off, err = h.Name.unpack(msg, off)
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

func (h *ResourceHdr) pack(msg []byte, compression map[string]uint16, compressionOff int, dataLen uint16) ([]byte, error) {
	msg, err := h.Name.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("name", err)
	}
	msg = packUint16(msg, uint16(h.Type))
	msg = packUint16(msg, uint16(h.Class))
	msg = packUint32(msg, h.TTL)

	// ignore h.Length
	msg = packUint16(msg, dataLen)
	return msg, nil
}

func (h *ResourceHdr) packLen(compression map[string]uint16) (int, error) {
	l, err := h.Name.packLen(compression)
	if err != nil {
		return 0, err
	}
	return l + 10, nil // type, class, ttl (uint32), length
}

func (h *ResourceHdr) copyFrom(h2 *ResourceHdr) {
	h.Name.CopyFrom(&h2.Name)
	h.Type = h2.Type
	h.Class = h2.Class
	h.TTL = h2.TTL
	h.Length = h2.Length
}

type A struct {
	ResourceHdr
	A [4]byte
}

var _ Resource = (*A)(nil)

func (r *A) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *A) reset() {
	r.ResourceHdr.reset()
	r.A = [4]byte{}
}

func (r *A) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg = packBytes(msg, r.A[:])
	return msg, nil
}

func (r *A) unpackBody(msg []byte, off int) (int, error) {
	return unpackBytesMsg(msg, off, r.A[:])
}

func (r *A) Copy() Resource {
	n := NewA()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)
	n.A = r.A
	return n
}

func (r *A) packBodyLen(compression map[string]uint16) (int, error) {
	return 4, nil
}

type AAAA struct {
	ResourceHdr
	AAAA [16]byte
}

var _ Resource = (*AAAA)(nil)

func (r *AAAA) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *AAAA) reset() {
	r.ResourceHdr.reset()
	r.AAAA = [16]byte{}
}

func (r *AAAA) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg = packBytes(msg, r.AAAA[:])
	return msg, nil
}

func (r *AAAA) unpackBody(msg []byte, off int) (int, error) {
	return unpackBytesMsg(msg, off, r.AAAA[:])
}

func (r *AAAA) Copy() Resource {
	n := NewAAAA()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)
	n.AAAA = r.AAAA
	return n
}

func (r *AAAA) packBodyLen(compression map[string]uint16) (int, error) {
	return 16, nil
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

func (r *NAMEResource) reset() {
	r.ResourceHdr.reset()
	r.NameData.Reset()
}

func (r *NAMEResource) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg, err := r.NameData.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("data", err)
	}
	return msg, nil
}

func (r *NAMEResource) unpackBody(msg []byte, off int) (int, error) {
	off, err := r.NameData.unpack(msg, off)
	if err != nil {
		return off, newSectionErr("data", err)
	}
	return off, nil
}

func (r *NAMEResource) Copy() Resource {
	n := NewNAME()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)
	n.NameData.CopyFrom(&r.NameData)
	return n
}

func (r *NAMEResource) packBodyLen(compression map[string]uint16) (int, error) {
	return r.NameData.packLen(compression)
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

func (r *SOA) reset() {
	r.ResourceHdr.reset()
	r.NS.Reset()
	r.MBox.Reset()
	r.Serial = 0
	r.Refresh = 0
	r.Retry = 0
	r.Expire = 0
	r.MinTTL = 0
}

func (r *SOA) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg, err := r.NS.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("ns", err)
	}
	msg, err = r.MBox.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("mbox", err)
	}
	msg = packUint32(msg, r.Serial)
	msg = packUint32(msg, r.Refresh)
	msg = packUint32(msg, r.Retry)
	msg = packUint32(msg, r.Expire)
	msg = packUint32(msg, r.MinTTL)
	return msg, nil
}

func (r *SOA) unpackBody(msg []byte, off int) (int, error) {
	var err error
	off, err = r.NS.unpack(msg, off)
	if err != nil {
		return 0, newSectionErr("ns", err)
	}
	off, err = r.MBox.unpack(msg, off)
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
	return off, nil
}

func (r *SOA) Copy() Resource {
	n := NewSOA()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)

	n.NS.CopyFrom(&r.NS)
	n.MBox.CopyFrom(&r.MBox)
	n.Serial = r.Serial
	n.Refresh = r.Refresh
	n.Retry = r.Retry
	n.Expire = r.Expire
	n.MinTTL = r.MinTTL
	return n
}

func (r *SOA) packBodyLen(compression map[string]uint16) (int, error) {
	s := 0
	l, err := r.NS.packLen(compression)
	if err != nil {
		return 0, newSectionErr("ns", err)
	}
	s += l

	l, err = r.MBox.packLen(compression)
	if err != nil {
		return 0, newSectionErr("mbox", err)
	}
	s += l
	s += 20
	return s, nil
}

type MX struct {
	ResourceHdr
	Pref uint16
	MX   Name
}

var _ Resource = (*MX)(nil)

func (r *MX) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *MX) reset() {
	r.ResourceHdr.reset()
	r.Pref = 0
	r.MX.Reset()
}

func (r *MX) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg = packUint16(msg, r.Pref)
	msg, err := r.MX.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("mx", err)
	}
	return msg, nil
}

func (r *MX) unpackBody(msg []byte, off int) (int, error) {
	var err error
	r.Pref, off, err = unpackUint16Msg(msg, off)
	if err != nil {
		return 0, newSectionErr("pref", err)
	}
	off, err = r.MX.unpack(msg, off)
	if err != nil {
		return 0, newSectionErr("mx", err)
	}
	return off, nil
}

func (r *MX) Copy() Resource {
	n := NewMX()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)

	n.Pref = r.Pref
	n.MX.CopyFrom(&r.MX)
	return n
}

func (r *MX) packBodyLen(compression map[string]uint16) (int, error) {
	s := 2
	l, err := r.MX.packLen(compression)
	if err != nil {
		return 0, newSectionErr("mx", err)
	}
	s += l
	return s, nil
}

type SRV struct {
	ResourceHdr
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Name // Not compressed as per RFC 2782.
}

var _ Resource = (*SRV)(nil)

func (r *SRV) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *SRV) reset() {
	r.ResourceHdr.reset()
	r.Priority = 0
	r.Weight = 0
	r.Port = 0
	r.Target.Reset()
}

func (r *SRV) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg = packUint16(msg, r.Priority)
	msg = packUint16(msg, r.Weight)
	msg = packUint16(msg, r.Port)
	msg, err := r.Target.pack(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("target", err)
	}
	return msg, nil
}

func (r *SRV) unpackBody(msg []byte, off int) (int, error) {
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
	off, err = r.Target.unpack(msg, off)
	if err != nil {
		return 0, newSectionErr("target", err)
	}
	return off, nil
}

func (r *SRV) Copy() Resource {
	n := NewSRV()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)

	n.Priority = r.Priority
	n.Weight = r.Weight
	n.Port = r.Port
	n.Target.CopyFrom(&r.Target)
	return n
}

func (r *SRV) packBodyLen(compression map[string]uint16) (int, error) {
	s := 6

	// RFC 2782:
	// Target: The domain name of the target host. [...]
	// Unless and until permitted by future standards action,
	// name compression is not to be used for this field."
	l, err := r.Target.packLen(nil)
	if err != nil {
		return 0, newSectionErr("target", err)
	}
	s += l
	return s, nil
}

type RawResource struct {
	ResourceHdr
	Data pool.Buffer
}

var _ Resource = (*RawResource)(nil)

func (r *RawResource) Hdr() *ResourceHdr {
	return &r.ResourceHdr
}

func (r *RawResource) reset() {
	r.ResourceHdr.reset()
	if r.Data != nil {
		pool.ReleaseBuf(r.Data)
		r.Data = nil
	}
}

func (rr *RawResource) packBody(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg = packBytes(msg, rr.Data)
	return msg, nil
}

func (r *RawResource) unpackBody(msg []byte, off int) (int, error) {
	b, off, err := unpackBytesMsgToBuffer(msg, off, int(r.Length))
	if err != nil {
		return off, newSectionErr("data", err)
	}
	r.Data = b
	return off, nil
}

func (r *RawResource) Copy() Resource {
	n := NewRaw()
	n.ResourceHdr.copyFrom(&r.ResourceHdr)

	n.Data = pool.CopyBuf(r.Data)
	return n
}

func (r *RawResource) packBodyLen(compression map[string]uint16) (int, error) {
	return len(r.Data), nil
}

func packRR(r Resource, msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	msg, err := r.Hdr().pack(msg, compression, compressionOff, 0)
	if err != nil {
		return msg, newSectionErr("hdr", err)
	}
	dataLenOff := len(msg) - 2
	dataOff := len(msg)

	msg, err = r.packBody(msg, compression, compressionOff)
	if err != nil {
		return msg, newSectionErr("body", err)
	}

	dataLen := len(msg) - dataOff
	if dataLen > math.MaxUint16 {
		return msg, errResTooLong
	}
	putUint16(msg[dataLenOff:dataLenOff+2], uint16(dataLen))
	return msg, nil
}

func packRRLen(r Resource, compression map[string]uint16) (int, error) {
	s := 0
	l, err := r.Hdr().packLen(compression)
	if err != nil {
		return 0, newSectionErr("hdr", err)
	}
	s += l

	l, err = r.packBodyLen(compression)
	if err != nil {
		return 0, newSectionErr("body", err)
	}
	if l > math.MaxUint16 {
		return 0, errResTooLong
	}
	s += l

	return s, nil
}

// Unpack one rr starting at msg[off:].
// Return unpacked rr, next offset, error.
func UnpackResource(msg []byte, off int) (Resource, int, error) {
	hdr := newRrHdr()
	defer releaseRrHdr(hdr)
	return unpackResource(hdr, msg, off)
}

// hdr is a tmp buffer
func unpackResource(hdr *ResourceHdr, msg []byte, off int) (Resource, int, error) {
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
	r.Hdr().copyFrom(hdr)

	dataOff := off
	off, err = r.unpackBody(msg, off)
	if err != nil {
		ReleaseResource(r)
		return nil, off, err
	}
	if dataRead := off - dataOff; dataRead != int(hdr.Length) {
		ReleaseResource(r)
		return nil, off, errInvalidResourceBodyLen
	}
	return r, off, nil
}
