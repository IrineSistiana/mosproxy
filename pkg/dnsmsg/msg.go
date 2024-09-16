package dnsmsg

import (
	"slices"
	"sync"
)

const (
	headerBitQR = 1 << 15 // query/response (response=1)
	headerBitAA = 1 << 10 // authoritative
	headerBitTC = 1 << 9  // truncated
	headerBitRD = 1 << 8  // recursion desired
	headerBitRA = 1 << 7  // recursion available
	headerBitAD = 1 << 5  // authentic data
	headerBitCD = 1 << 4  // checking disabled
)

// DNS msg raw header.
type rawHeader struct {
	id          uint16
	bits        uint16
	questions   uint16
	answers     uint16
	authorities uint16
	additionals uint16
}

func (h *rawHeader) header() Header {
	return Header{
		ID:                 h.id,
		Response:           (h.bits & headerBitQR) != 0,
		OpCode:             OpCode(h.bits>>11) & 0xF,
		Authoritative:      (h.bits & headerBitAA) != 0,
		Truncated:          (h.bits & headerBitTC) != 0,
		RecursionDesired:   (h.bits & headerBitRD) != 0,
		RecursionAvailable: (h.bits & headerBitRA) != 0,
		AuthenticData:      (h.bits & headerBitAD) != 0,
		CheckingDisabled:   (h.bits & headerBitCD) != 0,
		RCode:              RCode(h.bits & 0xF),
	}
}

func (h *rawHeader) pack(msg []byte) (off int, err error) {
	if len(msg) < 12 {
		return 0, ErrSmallBuffer
	}
	putUint16(msg[0:2], h.id)
	putUint16(msg[2:4], h.bits)
	putUint16(msg[4:6], h.questions)
	putUint16(msg[6:8], h.answers)
	putUint16(msg[8:10], h.authorities)
	putUint16(msg[10:12], h.additionals)
	return 12, nil
}

func (h *rawHeader) unpack(msg []byte, off int) (int, error) {
	hdr := msg[off:]
	if len(hdr) < 12 {
		return 0, ErrSmallBuffer
	}
	off += 12
	h.id = unpackUint16(hdr[0:2])
	h.bits = unpackUint16(hdr[2:4])
	h.questions = unpackUint16(hdr[4:6])
	h.answers = unpackUint16(hdr[6:8])
	h.authorities = unpackUint16(hdr[8:10])
	h.additionals = unpackUint16(hdr[10:12])
	return off, nil
}

// Header is a representation of a DNS message header.
type Header struct {
	ID                 uint16
	Response           bool
	OpCode             OpCode
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticData      bool
	CheckingDisabled   bool
	RCode              RCode
}

func (m *Header) Pack() (id uint16, bits uint16) {
	id = m.ID
	bits = uint16(m.OpCode)<<11 | uint16(m.RCode)
	if m.RecursionAvailable {
		bits |= headerBitRA
	}
	if m.RecursionDesired {
		bits |= headerBitRD
	}
	if m.Truncated {
		bits |= headerBitTC
	}
	if m.Authoritative {
		bits |= headerBitAA
	}
	if m.Response {
		bits |= headerBitQR
	}
	if m.AuthenticData {
		bits |= headerBitAD
	}
	if m.CheckingDisabled {
		bits |= headerBitCD
	}
	return
}

// HeaderCount is a dns msg header section.
// Useful when manually unpacking a dns msg.
type HeaderCount struct {
	QD uint16
	AN uint16
	NS uint16
	AD uint16
}

func UnpackHdr(msg []byte, off int) (Header, HeaderCount, int, error) {
	var rh rawHeader
	off, err := rh.unpack(msg, off)
	if err != nil {
		return Header{}, HeaderCount{}, off, newSectionErr("header", err)
	}
	h := rh.header()
	hc := HeaderCount{
		QD: rh.questions,
		AN: rh.answers,
		NS: rh.authorities,
		AD: rh.additionals,
	}
	return h, hc, off, nil
}

type Msg struct {
	noCopy
	Header
	Questions   []*Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

func (m *Msg) Copy() *Msg {
	n := NewMsg()
	n.Header = m.Header

	n.Questions = slices.Grow(n.Questions, len(m.Questions))
	for _, q := range m.Questions {
		n.Questions = append(n.Questions, q.Copy())
	}

	copy := func(src, dst *[]Resource) {
		*dst = slices.Grow(*dst, len(*src))
		for _, rr := range *src {
			*dst = append(*dst, rr.Copy())
		}
	}
	copy(&m.Answers, &n.Answers)
	copy(&m.Authorities, &n.Authorities)
	copy(&m.Additionals, &n.Additionals)
	return n
}

var msgPool = sync.Pool{New: func() any { return new(Msg) }}

func NewMsg() *Msg {
	return msgPool.Get().(*Msg)
}

func ReleaseMsg(m *Msg) {
	m.Header = Header{}

	for _, q := range m.Questions {
		ReleaseQuestion(q)
	}
	clear(m.Questions)
	m.Questions = m.Questions[:0]

	for _, rs := range [...][]Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, r := range rs {
			ReleaseResource(r)
		}
		clear(rs)
	}
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
	msgPool.Put(m)
}

func UnpackMsg(msg []byte) (*Msg, error) {
	m := NewMsg()
	err := m.Unpack(msg)
	if err != nil {
		ReleaseMsg(m)
		return nil, err
	}
	return m, nil
}

func (m *Msg) Unpack(msg []byte) error {
	var off int
	var h rawHeader
	off, err := h.unpack(msg, off)
	if err != nil {
		return newSectionErr("header", err)
	}
	m.Header = h.header()

	for i := 0; i < int(h.questions); i++ {
		var q *Question
		q, off, err = UnpackQuestion(msg, off)
		if err != nil {
			return newSectionErr("questions", err)
		}
		m.Questions = append(m.Questions, q)
	}

	hdrBuffer := newRrHdr()
	defer releaseRrHdr(hdrBuffer)
	for i := 0; i < int(h.answers); i++ {
		var r Resource
		r, off, err = unpackResource(hdrBuffer, msg, off)
		hdrBuffer.reset()
		if err != nil {
			return newSectionErr("answers", err)
		}
		m.Answers = append(m.Answers, r)
	}
	for i := 0; i < int(h.authorities); i++ {
		var r Resource
		r, off, err = unpackResource(hdrBuffer, msg, off)
		hdrBuffer.reset()
		if err != nil {
			return newSectionErr("authorities", err)
		}
		m.Authorities = append(m.Authorities, r)
	}
	for i := 0; i < int(h.additionals); i++ {
		var r Resource
		r, off, err = unpackResource(hdrBuffer, msg, off)
		hdrBuffer.reset()
		if err != nil {
			return newSectionErr("additionals", err)
		}
		m.Additionals = append(m.Additionals, r)
	}
	return nil
}

var compressMapPool = sync.Pool{
	New: func() any {
		return make(map[string]uint16, 32)
	},
}

func newCompressionMap() map[string]uint16 {
	return compressMapPool.Get().(map[string]uint16)
}

func releaseCompressionMap(m map[string]uint16) {
	clear(m)
	compressMapPool.Put(m)
}

// Pack and append data into b.
// Size is the msg size limit. Upon reach the limit, no rr will be
// packed and the msg will be "Truncated". Minimum is 512. 0 means no limit.
func (m *Msg) Pack(b []byte, compression bool, size int) ([]byte, error) {
	msgOff := len(b)

	// Validate the lengths. It is very unlikely that anyone will try to
	// pack more than 65535 of any particular type, but it is possible and
	// we should fail gracefully.
	if len(m.Questions) > int(^uint16(0)) {
		return b, errTooManyQuestions
	}
	if len(m.Answers) > int(^uint16(0)) {
		return b, errTooManyAnswers
	}
	if len(m.Authorities) > int(^uint16(0)) {
		return b, errTooManyAuthorities
	}
	if len(m.Additionals) > int(^uint16(0)) {
		return b, errTooManyAdditionals
	}

	var h rawHeader
	h.id, h.bits = m.Header.Pack()
	h.questions = uint16(len(m.Questions))
	h.answers = uint16(len(m.Answers))
	h.authorities = uint16(len(m.Authorities))
	h.additionals = uint16(len(m.Additionals))

	if size > 0 && size < 512 {
		size = 512
	}

	var msgHdr = m.Header              // copy it, we may change the tc flag
	b = append(b, make([]byte, 12)...) // allocate header

	// Find edns0 first, this rr should not be truncated.
	var eDNS0Opt Resource
	if size > 0 {
		for i := len(m.Additionals) - 1; i >= 0; i-- {
			r := m.Additionals[i]
			if r.Hdr().Type == TypeOPT {
				eDNS0Opt = r
				break
			}
		}
		if eDNS0Opt != nil {
			l, err := eDNS0Opt.packBodyLen(nil)
			if err != nil {
				return b, newSectionErr("edns0", err)
			}
			size -= l
		}
	}

	var compressionMap map[string]uint16
	if compression && len(m.Questions)+len(m.Answers)+len(m.Authorities)+len(m.Additionals) > 1 {
		compressionMap = newCompressionMap()
		defer releaseCompressionMap(compressionMap)
	}

	section := "question"
	for _, q := range m.Questions {
		if size > 0 {
			l, err := q.packLen(compressionMap)
			if err != nil {
				return b, newSectionErr(section, err)
			}
			if len(b)+l > size {
				msgHdr.Truncated = true
				continue
			}
		}
		var err error
		if b, err = q.pack(b, compressionMap, msgOff); err != nil {
			return b, newSectionErr(section, err)
		}
	}

	packRRs := func(b []byte, rrs []Resource, skipEDNS0 bool) ([]byte, error) {
		for _, r := range rrs {
			if skipEDNS0 && r.Hdr().Type == TypeOPT {
				continue
			}
			if size > 0 {
				l, err := packRRLen(r, compressionMap)
				if err != nil {
					return b, err
				}
				if len(b)+l > size {
					msgHdr.Truncated = true
					continue
				}
			}
			var err error
			if b, err = packRR(r, b, compressionMap, msgOff); err != nil {
				return b, err
			}
		}
		return b, nil
	}
	b, err := packRRs(b, m.Answers, false)
	if err != nil {
		return b, newSectionErr("answers", err)
	}
	b, err = packRRs(b, m.Authorities, false)
	if err != nil {
		return b, newSectionErr("authority", err)
	}
	b, err = packRRs(b, m.Additionals, eDNS0Opt != nil)
	if err != nil {
		return b, newSectionErr("additional", err)
	}

	if eDNS0Opt != nil {
		var err error
		b, err = packRR(eDNS0Opt, b, compressionMap, msgOff)
		if err != nil {
			return b, newSectionErr("edns0", err)
		}
	}

	h.pack(b[msgOff : msgOff+12])
	return b, nil
}

// Pack length if no compression.
func (m *Msg) MaxPackLen() (s int, err error) {
	s += 12

	var l int
	for _, q := range m.Questions {
		l, err = q.packLen(nil)
		if err != nil {
			err = newSectionErr("question", err)
			return
		}
		s += l
	}

	secStr := [...]string{"answers", "authorities", "additionals"}
	for si, rrs := range [...][]Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, rr := range rrs {
			l, err = packRRLen(rr, nil)
			if err != nil {
				err = newSectionErr(secStr[si], err)
				return
			}
			s += l
		}
	}
	return
}

func PopEDNS0(m *Msg) Resource {
	end := len(m.Additionals) - 1
	for i := end; i >= 0; i-- {
		r := m.Additionals[i]
		if r.Hdr().Type == TypeOPT {
			m.Additionals[i] = m.Additionals[end]
			m.Additionals[end] = nil
			m.Additionals = m.Additionals[:end]
			return r
		}
	}
	return nil
}

func RemoveEDNS0(m *Msg) {
	if rr := PopEDNS0(m); rr != nil {
		ReleaseResource(rr)
	}
}
