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

func (m *Header) pack() (id uint16, bits uint16) {
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
	noCopy

	Header
	Questions   List[*Question]
	Answers     List[*Resource]
	Authorities List[*Resource]
	Additionals List[*Resource]
}

// Len is the msg length without compression.
func (m *Msg) Len() (l int) {
	if m == nil {
		return 0
	}
	l += 12 // header
	for n := m.Questions.Head(); n != nil; n = n.Next() {
		q := n.Value()
		if q != nil {
			l += q.len()
		}
	}

	for _, list := range [...]*List[*Resource]{&m.Answers, &m.Authorities, &m.Additionals} {
		for n := list.Head(); n != nil; n = n.Next() {
			r := n.Value()
			if r != nil {
				l += r.len()
			}
		}
	}
	return l
}

func (m *Msg) Copy() *Msg      { return m.copy(false) }
func (m *Msg) CopyNoOpt() *Msg { return m.copy(true) }
func (m *Msg) copy(noOpt bool) *Msg {
	if m == nil {
		return nil
	}
	newMsg := NewMsg()
	newMsg.Header = m.Header
	for n := m.Questions.Head(); n != nil; n = n.Next() {
		q := n.Value()
		if q != nil {
			newMsg.Questions.Add(q.Copy())
		}
	}
	for n := m.Answers.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r != nil {
			newMsg.Answers.Add(r.Copy())
		}
	}
	for n := m.Authorities.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r != nil {
			newMsg.Authorities.Add(r.Copy())
		}
	}
	for n := m.Additionals.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r != nil {
			if noOpt && r.Type == TypeOPT {
				continue
			}
			newMsg.Additionals.Add(r.Copy())
		}
	}
	return newMsg
}

var msgPool = sync.Pool{New: func() any { return new(Msg) }}

func NewMsg() *Msg {
	return msgPool.Get().(*Msg)
}

func ReleaseMsg(m *Msg) {
	for {
		n := m.Questions.Head()
		if n == nil {
			break
		}
		q := n.Value()
		m.Questions.Remove(n)
		if q != nil {
			ReleaseQuestion(q)
		}
	}
	for _, list := range [...]*List[*Resource]{&m.Answers, &m.Authorities, &m.Additionals} {
		for {
			n := list.Head()
			if n == nil {
				break
			}
			r := n.Value()
			list.Remove(n)
			if r != nil {
				ReleaseRR(r)
			}
		}
	}
	m.Header = Header{}
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
			return newSectionErr("question", err)
		}
		m.Questions.Add(q)
	}

	for i := 0; i < int(h.answers); i++ {
		var r *Resource
		r, off, err = unpackRawResource(msg, off)
		if err != nil {
			return newSectionErr("answers", err)
		}
		m.Answers.Add(r)
	}

	for i := 0; i < int(h.authorities); i++ {
		var r *Resource
		r, off, err = unpackRawResource(msg, off)
		if err != nil {
			return newSectionErr("authorities", err)
		}
		m.Authorities.Add(r)
	}

	for i := 0; i < int(h.additionals); i++ {
		var r *Resource
		r, off, err = unpackRawResource(msg, off)
		if err != nil {
			return newSectionErr("additionals", err)
		}
		m.Additionals.Add(r)
	}
	return nil
}

var compressMapPool = sync.Pool{
	New: func() any {
		return make(map[string]uint16, 50)
	},
}

func getCompressionMap() map[string]uint16 {
	return compressMapPool.Get().(map[string]uint16)
}

func releaseCompressionMap(m map[string]uint16) {
	clear(m)
	compressMapPool.Put(m)
}

type MsgSection uint8

const (
	SectionAnswer MsgSection = iota
	SectionAuthority
	SectionAdditional
)

type PackFilter func(sec MsgSection, rr *Resource) bool

func (m *Msg) Pack(b []byte, compression bool, size int) (int, error) {
	return m.PackFilter(b, compression, size, nil)
}

// Pack m into b. Returns the msg size.
// compression == true will only compress rr header.
// Size is the msg size limit. Upon reach the limit, no rr will be
// packed and the msg will be "Truncated". Minimum is 512. 0 means no limit.
// If ignoreRr returns true, this rr will be ignored during packing.
// The size of b should be m.Len(). If b is not big enough, an error will be returned.
// Without compression, the msg will have the size of m.Len().
// TODO: Calculate compressed length?
func (m *Msg) PackFilter(
	b []byte,
	compression bool,
	size int,
	ignoreRr func(sec MsgSection, rr *Resource) bool,
) (int, error) {
	if size > 0 && size < 512 {
		size = 512
	}

	var msgHdr = m.Header
	off := 12
	if len(b) < off {
		return 0, newSectionErr("header", ErrSmallBuffer)
	}

	var edns0Opt *Resource
	if size > 0 {
		edns0Opt = m.popEdns0()
		if edns0Opt != nil {
			size -= edns0Opt.len()
		}
	}

	// Validate the lengths. It is very unlikely that anyone will try to
	// pack more than 65535 of any particular type, but it is possible and
	// we should fail gracefully.
	var (
		questions   int
		answers     int
		authorities int
		additionals int
	)
	if edns0Opt != nil {
		additionals++
	}
	var compressionMap map[string]uint16
	if compression {
		compressionMap = getCompressionMap()
		defer releaseCompressionMap(compressionMap)
	}
	for n := m.Questions.Head(); n != nil; n = n.Next() {
		q := n.Value()
		if q == nil {
			continue
		}
		if size > 0 && off+q.len() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = q.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("question", err)
		}
		questions++
		if questions > 65535 {
			return off, errTooManyQuestions
		}
	}

	for n := m.Answers.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r == nil {
			continue
		}
		if ignoreRr != nil && ignoreRr(SectionAnswer, r) {
			continue
		}
		if size > 0 && off+r.len() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("answer", err)
		}
		answers++
		if answers > 65535 {
			return off, errTooManyAnswers
		}
	}
	for n := m.Authorities.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r == nil {
			continue
		}
		if ignoreRr != nil && ignoreRr(SectionAuthority, r) {
			continue
		}
		if size > 0 && off+r.len() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("authority", err)
		}
		authorities++
		if authorities > 65535 {
			return off, errTooManyAuthorities
		}
	}
	for n := m.Additionals.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r == nil {
			continue
		}
		if ignoreRr != nil && ignoreRr(SectionAdditional, r) {
			continue
		}
		if size > 0 && off+r.len() > size {
			msgHdr.Truncated = true
			continue
		}
		var err error
		if off, err = r.pack(b, off, compressionMap); err != nil {
			return off, newSectionErr("additional", err)
		}
		additionals++
		if additionals > 65535 {
			return off, errTooManyAdditionals
		}
	}

	if edns0Opt != nil {
		ignoreOpt := ignoreRr != nil && ignoreRr(SectionAdditional, edns0Opt)
		if !ignoreOpt {
			m.Additionals.Add(edns0Opt)
			var err error
			if off, err = edns0Opt.pack(b, off, compressionMap); err != nil {
				return off, newSectionErr("additional", err)
			}
		}
	}

	var h header
	h.id, h.bits = msgHdr.pack()
	h.questions = uint16(questions)
	h.answers = uint16(answers)
	h.authorities = uint16(authorities)
	h.additionals = uint16(additionals)
	h.pack(b[:12])
	return off, nil
}

func (m *Msg) popEdns0() *Resource {
	for n := m.Additionals.Tail(); n != nil; n = n.Prev() {
		r := n.Value()
		if r == nil {
			continue
		}
		if r.Type == TypeOPT {
			m.Additionals.Remove(n)
			return r
		}
	}
	return nil
}
