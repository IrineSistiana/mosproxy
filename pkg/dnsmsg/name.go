package dnsmsg

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
)

var (
	errNameBufTooShort = errors.New("name buffer too short")
	errNameBufTooLong  = errors.New("name buffer too long")
	errDirtyName       = errors.New("dirty name buffer")
)

var namePool = sync.Pool{}

// Name is a dns name.
type Name struct {
	b []byte   // raw data
	s [][]byte // labels, reference to b
}

// Returns the domain name in wire format. Do not modify the it.
func (n *Name) Data() []byte {
	return n.b
}

// Returns the labels. Do not modify the it.
func (n *Name) Labels() [][]byte {
	return n.s
}

func (n *Name) dirty() bool {
	return len(n.b) > 0 || len(n.s) > 0
}

// Clear all data in n.
// n will become empty and unfinished.
func (n *Name) Reset() {
	clear(n.b)
	n.b = n.b[:0]
	clear(n.s)
	n.s = n.s[:0]
}

func (n *Name) CopyFrom(n2 Name) {
	n.Reset()
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
	var unsafeStr string // lazy init
	for i := 0; i < len(n.b); {
		l := int(n.b[i])
		if l == 0 { // End of name.
			if i != len(n.b)-1 {
				return msg, errNameBufTooLong
			}
			return packByte(msg, 0), nil
		}

		if compression != nil {
			// We can only compress domain suffixes starting with a new
			// segment. A pointer is two bytes with the two most significant
			// bits set to 1 to indicate that it is a pointer.
			if ptr, ok := compression[string(n.b[i:])]; ok {
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
				compression[unsafeStr[i:]] = uint16(newPtr)
			}
		}

		msg = packBytes(msg, n.b[i:i+1+l])
		i += 1 + l
	}
	return msg, errNameBufTooShort
}

func (n *Name) packLen(compression map[string]uint16) (int, error) {
	for i := 0; i < len(n.b); {
		l := int(n.b[i])
		if l == 0 {
			if i != len(n.b)-1 {
				return 0, errNameBufTooLong
			}
			return i + 1, nil
		}
		if compression != nil {
			_, ok := compression[string(n.b[i:])]
			if ok {
				return i + 2, nil
			}
		}
		i += 1 + l
	}
	return 0, errNameBufTooShort
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
	err := n.parseLabels()
	if err != nil {
		return off, fmt.Errorf("internal error: %w", err)
	}
	return newOff, nil
}

func (n *Name) ToLower() {
	for _, seg := range n.s {
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
	for i, seg := range n.s {
		if i > 0 {
			b = append(b, '.')
		}
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
				dst = append(dst, '\\')
				switch {
				case b < 10:
					dst = append(dst, "00"...)
				case b < 100:
					dst = append(dst, '0')
				}
				dst = strconv.AppendUint(dst, uint64(b), 10)
			}
		}
	}
	return dst
}

func appendLabelTo[T []byte | string](n *Name, s T) error {
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
	n.b = append(n.b, byte(l))
	n.b = append(n.b, s...)
	return nil
}

func (n *Name) parseLabels() error {
	for i := 0; i < len(n.b); {
		l := int(n.b[i])
		if l == 0 {
			if i != len(n.b)-1 {
				return errNameBufTooLong
			}
			return nil
		}
		start := i + 1
		end := start + l
		n.s = append(n.s, n.b[start:end])
		i += 1 + l
	}
	return errNameBufTooShort
}

func (n *Name) Parse(s string) error {
	return ParseName(n, s)
}

// Parse a readable domain to empty n.
// Empty s or "." will be the root domain.
// Both FQDN/non-FQDN are OK.
// escaping "\", e.g. "\.", "\DDD", is supported.
func ParseName[T []byte | string](n *Name, s T) error {
	if n.dirty() {
		return errDirtyName
	}

	if len(s) == 0 || len(s) == 1 && s[0] == '.' {
		n.b = append(n.b, 0)
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
					if n+3 <= len(s) {
						i += 3
						c, ok = parseDDD(s[n : n+3])
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

	n.b = append(n.b, 0)
	err := n.parseLabels()
	if err != nil {
		return fmt.Errorf("internal error: %w", err)
	}
	return nil
}

func ParseNameLabels[T []byte | string](n *Name, ls []T) error {
	if n.dirty() {
		return errDirtyName
	}
	for _, l := range ls {
		err := appendLabelTo(n, l)
		if err != nil {
			return err
		}
	}
	n.b = append(n.b, 0)
	err := n.parseLabels()
	if err != nil {
		return fmt.Errorf("internal error: %w", err)
	}
	return nil
}

func ParseNameRaw[T []byte | string](n *Name, s T) error {
	if n.dirty() {
		return errDirtyName
	}
	n.b = append(n.b, s...)
	return n.parseLabels()
}
