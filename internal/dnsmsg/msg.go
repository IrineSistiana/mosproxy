package dnsmsg

import (
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

type header struct {
	id          uint16
	bits        uint16
	questions   uint16
	answers     uint16
	authorities uint16
	additionals uint16
}

func (h *header) header() Header {
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

func (h *header) pack(msg []byte) (off int, err error) {
	if len(msg) < 12 {
		return 0, ErrSmallBuffer
	}
	putUint16(msg[0:2], h.id)
	putUint16(msg[2:4], h.bits)
	putUint16(msg[4:6], h.questions)
	putUint16(msg[6:8], h.answers)
	putUint16(msg[8:10], h.authorities)
	putUint16(msg[10:12], h.additionals)
	return 8, nil
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

func (h *header) unpack(msg []byte, off int) (int, error) {
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

type Msg struct {
	Header
	Questions   []*Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

// Len is the msg length without compression.
func (m *Msg) Len() (l int) {
	if m == nil {
		return 0
	}
	l += 12 // header

	for _, q := range m.Questions {
		l += q.Len()
	}

	for _, rs := range [...][]Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, r := range rs {
			l += r.packLen()
		}
	}
	return l
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
	var h header
	off, err := h.unpack(msg, off)
	if err != nil {
		return newSectionErr("header", err)
	}
	m.Header = h.header()

	for i := 0; i < int(h.questions); i++ {
		var q *Question
		q, off, err = unpackQuestion(msg, off)
		if err != nil {
			return newSectionErr("questions", err)
		}
		m.Questions = append(m.Questions, q)
	}

	for i := 0; i < int(h.answers); i++ {
		var r Resource
		r, off, err = unpackResource(msg, off)
		if err != nil {
			return newSectionErr("answers", err)
		}
		m.Answers = append(m.Answers, r)
	}

	for i := 0; i < int(h.authorities); i++ {
		var r Resource
		r, off, err = unpackResource(msg, off)
		if err != nil {
			return newSectionErr("authorities", err)
		}
		m.Authorities = append(m.Authorities, r)
	}

	for i := 0; i < int(h.additionals); i++ {
		var r Resource
		r, off, err = unpackResource(msg, off)
		if err != nil {
			return newSectionErr("additionals", err)
		}
		m.Additionals = append(m.Additionals, r)
	}
	return nil
}

var compressMapPool = sync.Pool{
	New: func() any {
		return make(map[string]uint16, 50)
	},
}

func newCompressionMap() map[string]uint16 {
	return compressMapPool.Get().(map[string]uint16)
}

func releaseCompressionMap(m map[string]uint16) {
	clear(m)
	compressMapPool.Put(m)
}

// Pack m into b. Returns the msg size.
// compression == true will only compress rr header.
// Size is the msg size limit. Upon reach the limit, no rr will be
// packed and the msg will be "Truncated". Minimum is 512. 0 means no limit.
// The size of b should be m.Len(). If b is not big enough, an error will be returned.
// Without compression, the msg will have the size of m.Len().
// TODO: Calculate compressed length?
func (m *Msg) Pack(b []byte, compression bool, size int) (int, error) {
	// Validate the lengths. It is very unlikely that anyone will try to
	// pack more than 65535 of any particular type, but it is possible and
	// we should fail gracefully.
	if len(m.Questions) > int(^uint16(0)) {
		return 0, errTooManyQuestions
	}
	if len(m.Answers) > int(^uint16(0)) {
		return 0, errTooManyAnswers
	}
	if len(m.Authorities) > int(^uint16(0)) {
		return 0, errTooManyAuthorities
	}
	if len(m.Additionals) > int(^uint16(0)) {
		return 0, errTooManyAdditionals
	}

	var h header
	h.id, h.bits = m.Header.Pack()
	h.questions = uint16(len(m.Questions))
	h.answers = uint16(len(m.Answers))
	h.authorities = uint16(len(m.Authorities))
	h.additionals = uint16(len(m.Additionals))

	if size > 0 && size < 512 {
		size = 512
	}

	var msgHdr = m.Header
	off := 12
	if len(b) < off {
		return 0, newSectionErr("header", ErrSmallBuffer)
	}

	var edns0Opt Resource
	if size > 0 {
		edns0Opt = PopEDNS0(m)
		if edns0Opt != nil {
			size -= edns0Opt.packLen()
		}
	}

	var compressionMap map[string]uint16
	if compression {
		compressionMap = newCompressionMap()
		defer releaseCompressionMap(compressionMap)
	}
	for _, q := range m.Questions {
		if size > 0 && off+q.Len() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = q.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("question", err)
		}
	}

	for _, r := range m.Answers {
		if size > 0 && off+r.packLen() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("answer", err)
		}
	}
	for _, r := range m.Authorities {
		if size > 0 && off+r.packLen() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("authority", err)
		}
	}
	for _, r := range m.Additionals {
		if size > 0 && off+r.packLen() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("additional", err)
		}
	}

	if edns0Opt != nil {
		m.Additionals = append(m.Additionals, edns0Opt)
		var err error
		if off, err = edns0Opt.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("additional", err)
		}
	}

	h.pack(b[:12])
	return off, nil
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
