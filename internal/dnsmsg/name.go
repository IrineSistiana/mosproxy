package dnsmsg

import (
	"bytes"
	"strconv"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

// Name is a reusable buffer from bytespool.
type Name []byte

func ReleaseName(n Name) {
	pool.ReleaseBuf(pool.Buffer(n))
}

// Always returns 1~255.
func (n Name) PackLen() int {
	l := len(n)
	if l > 254 {
		l = 254 // invalid length, let packName() fail
	}
	return l + 1
}

// copied and from dnsmessage.Name.pack.
// Note: compression map is valid when name is not changed.
func (n Name) pack(msg []byte, off int, compression map[string]uint16) (int, error) {
	var unsafeStr string // lazy init

	scanner := NewNameScanner(n)
	for scanner.Scan() {
		seg := scanner.Label()
		labelStart := scanner.LabelOff()
		// We can only compress domain suffixes starting with a new
		// segment. A pointer is two bytes with the two most significant
		// bits set to 1 to indicate that it is a pointer.
		if compression != nil {
			if ptr, ok := compression[string(n[labelStart:])]; ok {
				// Hit. Emit a pointer instead of the rest of
				// the domain.
				return packNamePtr(msg, off, [2]byte{byte(ptr>>8 | 0xC0), byte(ptr)})
			}

			// Miss. Add the suffix to the compression table if the
			// offset can be stored in the available 14 bits.
			newPtr := off
			if newPtr <= int(^uint16(0)>>2) {
				if len(unsafeStr) == 0 {
					unsafeStr = bytes2StrUnsafe(n)
				}
				compression[unsafeStr[labelStart:]] = uint16(newPtr)
			}
		}

		var err error
		off, err = packByte(msg, off, byte(len(seg)))
		if err != nil {
			return off, err
		}
		off, err = packBytes(msg, off, seg)
		if err != nil {
			return off, err
		}
	}
	if err := scanner.Err(); err != nil {
		return off, err
	}
	return packByte(msg, off, 0)
}

func ToLowerName(n []byte) error {
	scanner := NewNameScanner(n)
	for scanner.Scan() {
		asciiToLower(scanner.Label())
	}
	return scanner.Err()
}

// Convert n from wire format to common readable format.
// Root domain will be '.' .
// Labels will be split by '.' .
// No '.' at the end of the name.
// Unprintable characters will be escaped as "\DDD".
// '.' and '\' will be "\.", "\\".
// If n is invalid, returns nil, err.
func ToReadable(n []byte) (pool.Buffer, error) {
	if len(n) == 0 {
		b := pool.GetBuf(1)
		b[0] = '.'
		return b, nil
	}
	b := pool.GetBuf(1024)[:0]
	scanner := NewNameScanner(n)
	started := false
	for scanner.Scan() {
		if started {
			b = append(b, '.')
		}
		started = true
		b = appendEscapedLabel(b, scanner.Label())
	}
	if err := scanner.Err(); err != nil {
		pool.ReleaseBuf(b)
		return nil, err
	}
	return b, nil
}

func appendEscapedLabel(dst []byte, label []byte) []byte {
	for _, b := range label {
		if isPrintableLabelChar(b) {
			dst = append(dst, b)
		} else {
			switch b {
			case '.':
				dst = append(dst, "\\."...)
			case '\\':
				dst = append(dst, "\\\\"...)
			default:
				dst = strconv.AppendUint(dst, uint64(b), 10)
			}
		}
	}
	return dst
}

type NameBuilder struct {
	buf [254]byte
	l   uint8
}

func (b *NameBuilder) AppendLabel(s []byte) error {
	l := len(s)
	if l == 0 {
		return errZeroSegLen
	}
	if l > 63 {
		return errSegTooLong
	}

	labelStart := int(b.l)
	labelEnd := labelStart + 1 + l
	if labelEnd > 253 {
		return errNameTooLong
	}

	b.buf[labelStart] = byte(l)
	copy(b.buf[labelStart+1:], s)
	b.l = uint8(labelEnd)
	return nil
}

func (b *NameBuilder) Reset() {
	b.l = 0
}

// Empty s or "." will be the root domain.
// Both FQDN/non-FQDN are OK.
//
// Note: escaping ("\.", "\DDD" etc.) is not supported yet and
// will be parsed as part of the label. Which is not as expected.
// TODO: Support escaping or return an error.
func (b *NameBuilder) ParseReadable(s []byte) error {
	b.Reset()

	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}

	if len(s) == 0 {
		return nil
	}

	off := 0
	for off < len(s) {
		i := bytes.IndexByte(s[off:], '.')
		var label []byte
		if i > 0 {
			label = s[off : off+i]
		} else {
			label = s[off:]
		}
		err := b.AppendLabel(label)
		if err != nil {
			return err
		}
		off += len(label) + 1
	}
	return nil
}

func (b *NameBuilder) Parse(labels [][]byte) error {
	b.Reset()
	if len(labels) == 0 {
		return nil
	}
	for _, label := range labels {
		err := b.AppendLabel(label)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *NameBuilder) Data() []byte {
	return b.buf[:b.l]
}

func (b *NameBuilder) ToName() Name {
	buf := pool.GetBuf(int(b.l))
	copy(buf, b.buf[:])
	return Name(buf)
}

// copied and modified from dnsmessage
// unpack unpacks a domain name.
func (n *NameBuilder) unpack(msg []byte, off int) (int, error) {
	// currOff is the current working offset.
	currOff := off

	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

	// ptr is the number of pointers followed.
	var ptr int

	// Name is a slice representation of the name data.
	name := n.buf[:0]

Loop:
	for {
		if currOff >= len(msg) {
			return off, errBaseLen
		}
		c := int(msg[currOff])
		currOff++
		switch c & 0xC0 {
		case 0x00: // String segment
			if c == 0x00 {
				// A zero length signals the end of the name.
				break Loop
			}
			endOff := currOff + c
			if endOff > len(msg) {
				return off, errCalcLen
			}
			if len(name)+1+c+1 > 255 {
				return off, errNameTooLong
			}
			name = append(name, byte(c))
			name = append(name, msg[currOff:endOff]...)
			currOff = endOff
		case 0xC0: // Pointer
			if currOff >= len(msg) {
				return off, errInvalidPtr
			}
			c1 := msg[currOff]
			currOff++
			if ptr == 0 {
				newOff = currOff
			}
			// Don't follow too many pointers, maybe there's a loop.
			if ptr++; ptr > 10 {
				return off, errTooManyPtr
			}
			currOff = (c^0xC0)<<8 | int(c1)
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return off, errReserved
		}
	}

	if ptr == 0 {
		newOff = currOff
	}
	n.l = uint8(len(name))
	return newOff, nil
}

func unpackName(msg []byte, off int) (Name, int, error) {
	var n NameBuilder
	off, err := n.unpack(msg, off)
	if err != nil {
		return nil, off, err
	}
	return n.ToName(), off, nil
}

type NameScanner struct {
	n   []byte
	off int
	err error

	label    []byte
	labelOff int
}

func NewNameScanner(n []byte) NameScanner {
	return NameScanner{n: n}
}

func (s *NameScanner) Scan() bool {
	s.label = nil
	if len(s.n) > 254 {
		s.err = errNameTooLong
		return false
	}
	if s.off > len(s.n)-1 {
		return false
	}

	labelLen := int(s.n[s.off])
	if labelLen == 0 {
		s.err = errZeroSegLen
		return false
	}
	if labelLen > 63 {
		s.err = errInvalidLabelLen
		return false
	}

	labelStart := s.off + 1
	labelEnd := labelStart + labelLen
	if labelEnd > len(s.n) {
		s.err = errInvalidLabelLen
		return false
	}

	s.label = s.n[labelStart:labelEnd]
	s.labelOff = labelStart
	s.off = labelEnd
	return true
}

func (s *NameScanner) Label() []byte {
	return s.label
}

func (s *NameScanner) LabelOff() int {
	return s.labelOff
}

func (s *NameScanner) Err() error {
	return s.err
}
