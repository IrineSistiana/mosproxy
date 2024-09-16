package dnsmsg

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
)

var (
	errUnfinishedName = errors.New("unfinished name")
	errFinishedName   = errors.New("finished name")
	errDirtyName      = errors.New("dirty name buffer")
)

var namePool = sync.Pool{}

// Name is a dns name.
// Has 3 statuses:
//
// empty: new name with zero data. (NewName())
//
// unfinished: has data but not finished. (AppendLabel())
//
// finished: has data and is ready to be packed. (Finish(), Parse())
type Name struct {
	ok bool
	b  []byte  // data
	s  []uint8 // idx
}

// Report whether n is finished or not.
func (n *Name) Finished() bool {
	return n.ok
}

// Returns the domain name in wire format
func (n *Name) Data() []byte {
	return n.b
}

// Returns the label indexes.
func (n *Name) LabelIdx() []uint8 {
	return n.s
}

func (n *Name) dirty() bool {
	return len(n.b) > 0 || len(n.s) > 0
}

// Clear all data in n.
// n will become empty and unfinished.
func (n *Name) Reset() {
	n.ok = false
	clear(n.b)
	n.b = n.b[:0]
	clear(n.s)
	n.s = n.s[:0]
}

func (n *Name) CopyFrom(n2 *Name) {
	n.Reset()
	n.ok = n2.ok
	n.b = append(n.b, n2.b...)
	n.s = append(n.s, n2.s...)
}

// Get a empty name from buffer pool.
func NewName() *Name {
	n, ok := namePool.Get().(*Name)
	if !ok {
		n = new(Name)
	}
	return n
}

// Release this name to buffer pool.
func ReleaseName(n *Name) {
	n.Reset()
	namePool.Put(n)
}

// copied and from dnsmessage.Name.pack.
// Note: compression map is valid when name is not changed.
func (n *Name) pack(msg []byte, compression map[string]uint16, compressionOff int) ([]byte, error) {
	if !n.ok {
		return msg, errUnfinishedName
	}

	if compression == nil {
		return packBytes(msg, n.b), nil
	}

	var unsafeStr string // lazy init
	for i := 1; i < len(n.s); i++ {
		start := n.s[i-1]
		end := n.s[i]
		seg := n.b[start:end]

		// We can only compress domain suffixes starting with a new
		// segment. A pointer is two bytes with the two most significant
		// bits set to 1 to indicate that it is a pointer.
		if ptr, ok := compression[string(n.b[start:])]; ok {
			// Hit. Emit a pointer instead of the rest of
			// the domain.
			return packNamePtr(msg, byte(ptr>>8|0xC0), byte(ptr)), nil
		}

		// Miss. Add the suffix to the compression table if the
		// offset can be stored in the available 14 bits.
		newPtr := len(msg) - compressionOff
		if newPtr <= int(^uint16(0)>>2) {
			if len(unsafeStr) == 0 {
				unsafeStr = bytes2StrUnsafe(n.b)
			}
			compression[unsafeStr[start:]] = uint16(newPtr)
		}

		msg = packBytes(msg, seg)
	}
	return packByte(msg, 0), nil // suffix zero
}

func (n *Name) packLen(compression map[string]uint16) (int, error) {
	if !n.ok {
		return 0, errUnfinishedName
	}

	if compression == nil {
		return len(n.b), nil
	}

	l := 0
	for i := 1; i < len(n.s); i++ {
		start := n.s[i-1]
		end := n.s[i]
		seg := n.b[start:end]

		if _, ok := compression[string(n.b[start:])]; ok {
			return l + 2, nil
		}

		l += 1 + len(seg)
	}
	return l + 1, nil
}

// copied and modified from dnsmessage
// unpack unpacks a domain name.
func (n *Name) unpack(msg []byte, off int) (int, error) {
	if n.dirty() {
		return off, errDirtyName
	}

	// currOff is the current working offset.
	currOff := off

	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

	// ptr is the number of pointers followed.
	var ptr int

Loop:
	for {
		if currOff >= len(msg) {
			return off, errBaseLen
		}
		c := int(msg[currOff])
		currOff++
		switch c & 0xC0 {
		case 0x00: // String segment
			n.s = append(n.s, byte(len(n.b)))
			n.b = append(n.b, byte(c))
			if c == 0x00 {
				// A zero length signals the end of the name.
				break Loop
			}
			endOff := currOff + c
			if endOff > len(msg) {
				return off, errCalcLen
			}
			if len(n.b)+1+c+1 > 255 {
				return off, errNameTooLong
			}
			n.b = append(n.b, msg[currOff:endOff]...)
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
	n.ok = true
	return newOff, nil
}

func (n *Name) ToLower() {
	if !n.ok {
		return
	}
	for i := 1; i < len(n.s); i++ {
		start := n.s[i-1]
		end := n.s[i]
		seg := n.b[start:end]
		asciiToLower(seg)
	}
}

// Convert n from wire format to common readable format.
// Root domain will be '.' .
// Labels will be split by '.' .
// No '.' at the end of the name.
// Unprintable characters will be escaped as "\DDD".
// '.' and '\' will be "\.", "\\".
// If n is invalid, returns nil, err.
func (n *Name) AppendReadableTo(b []byte) []byte {
	for i := 0; i < len(n.s)-1; i++ {
		if i > 0 {
			b = append(b, '.')
		}
		start := n.s[i] + 1
		end := n.s[i+1]
		seg := n.b[start:end]
		b = appendEscapedLabel(b, seg)
	}

	if len(b) == 0 {
		b = append(b, '.')
	}
	return b
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

// Append label s to an empty or unfinished name.
func (n *Name) AppendLabel(s string) error {
	return appendLabelTo(n, s)
}

func appendLabelTo[T []byte | string](n *Name, s T) error {
	if n.ok {
		return errFinishedName
	}

	l := len(s)
	if l == 0 {
		return errZeroSegLen
	}
	if l > 63 {
		return errSegTooLong
	}

	labelStart := len(n.b)
	labelEnd := labelStart + 1 + l
	if labelEnd >= 255 {
		return errNameTooLong
	}
	n.s = append(n.s, byte(labelStart))
	n.b = append(n.b, byte(l))
	n.b = append(n.b, s...)
	return nil
}

// Finish append the suffix 0 to name.
// n will be a finished name.
// Calling on a finished name is noop.
func (n *Name) Finish() {
	if n.ok {
		return
	}
	n.s = append(n.s, byte(len(n.b)))
	n.b = append(n.b, 0)
	n.ok = true
}

// Parse a readable domain to empty n.
// Empty s or "." will be the root domain.
// Both FQDN/non-FQDN are OK.
// escaping "\", e.g. "\.", "\DDD", is supported.
func (n *Name) Parse(s string) error {
	if n.dirty() {
		return errDirtyName
	}

	if len(s) == 0 || len(s) == 1 && s[0] == '.' {
		n.Finish()
		return nil
	}

	var buf [63]byte
	p := 0
	for i := 0; i < len(s); i++ {
		var c byte
		var ok bool
		switch s[i] {
		case '\\':
			if n := i + 1; n < len(s) {
				nextChar := s[n]
				if nextChar == '.' || nextChar == '\\' { // "\." and "\\"
					i += 1
					c = nextChar
					ok = true
				} else { // "\DDD"
					if i+4 <= len(s) {
						i += 3
						c, ok = parseDDD(s[i+1 : i+4])
					}
				}
			}
		case '.':
			err := appendLabelTo(n, buf[:p])
			if err != nil {
				return err
			}
			p = 0
			continue
		default:
			c = s[i]
			ok = true
		}

		if !ok {
			return fmt.Errorf("invalid char at %d", i)
		}
		if p >= len(buf) {
			return errSegTooLong
		}

		buf[p] = c
		p++
	}

	if p > 0 { // still some data in buf, because s has no suffix "."
		err := appendLabelTo(n, buf[:p])
		if err != nil {
			return err
		}
	}

	n.Finish()
	return nil
}

type NameScanner struct {
	n     *Name
	r     bool
	p     int
	label []byte
}

func NewNameScanner(n *Name) NameScanner {
	return NameScanner{n: n}
}

func (s *NameScanner) Reverse() {
	s.r = true
	s.p = len(s.n.s) - 2
}

func (s *NameScanner) Scan() bool {
	if s.r {
		if s.p >= 0 {
			s.label = s.n.b[s.n.s[s.p]+1 : s.n.s[s.p+1]]
			s.p--
			return true
		}
		s.label = nil
		return false
	} else {
		if s.p <= len(s.n.s)-2 {
			s.label = s.n.b[s.n.s[s.p]+1 : s.n.s[s.p+1]]
			s.p++
			return true
		}
		s.label = nil
		return false
	}
}

func (s *NameScanner) Label() []byte {
	return s.label
}
