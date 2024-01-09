package dnsmsg

import "github.com/IrineSistiana/mosproxy/internal/pool"

const (
	nonEncodedNameMax = 254
)

// copied and from dnsmessage.Name.pack.
// Note: compression map is valid when name is not changed.
func packName(nameP *pool.Buffer, msg []byte, off int, compression map[string]uint16) (int, error) {
	name := nameP.B()

	l := len(name)
	if l > nonEncodedNameMax {
		return 0, errNameTooLong
	}

	// Add a trailing dot to canonicalize name.
	if l == 0 || name[l-1] != '.' {
		return 0, errNonCanonicalName
	}

	// Allow root domain.
	if name[0] == '.' && l == 1 {
		return packByte(msg, off, 0)
	}

	var nameAsStr string

	// Emit sequence of counted strings, chopping at dots.
	for i, begin := 0, 0; i < int(l); i++ {
		// Check for the end of the segment.
		if name[i] == '.' {
			// The two most significant bits have special meaning.
			// It isn't allowed for segments to be long enough to
			// need them.
			if i-begin >= 1<<6 {
				return off, errSegTooLong
			}

			// Segments must have a non-zero length.
			if i-begin == 0 {
				return off, errZeroSegLen
			}

			var err error
			off, err = packByte(msg, off, byte(i-begin))
			if err != nil {
				return off, err
			}
			off, err = packBytes(msg, off, name[begin:i])
			if err != nil {
				return off, err
			}

			begin = i + 1
			continue
		}

		// We can only compress domain suffixes starting with a new
		// segment. A pointer is two bytes with the two most significant
		// bits set to 1 to indicate that it is a pointer.
		if (i == 0 || name[i-1] == '.') && compression != nil {
			if ptr, ok := compression[string(name[i:l])]; ok {
				// Hit. Emit a pointer instead of the rest of
				// the domain.
				return packNamePtr(msg, off, [2]byte{byte(ptr>>8 | 0xC0), byte(ptr)})
			}

			// Miss. Add the suffix to the compression table if the
			// offset can be stored in the available 14 bits.
			newPtr := off
			if newPtr <= int(^uint16(0)>>2) {
				if nameAsStr == "" {
					nameAsStr = bytes2StrUnsafe(name)
				}
				compression[nameAsStr[i:]] = uint16(newPtr)
			}
		}
	}
	return packByte(msg, off, 0)
}

// copided and modified from dnsmessage
func unpackName(msg []byte, off int) (*pool.Buffer, int, error) {
	// currOff is the current working offset.
	currOff := off

	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

	// ptr is the number of pointers followed.
	var ptr int

	// Name is a slice representation of the name data.
	var buf [255]byte
	name := buf[:0]

Loop:
	for {
		if currOff >= len(msg) {
			return nil, off, errBaseLen
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
				return nil, off, errCalcLen
			}
			if len(name)+1+c > 255 {
				return nil, off, errNameTooLong
			}

			// Reject names containing dots.
			// See issue golang/go#56246
			for _, v := range msg[currOff:endOff] {
				if v == '.' {
					return nil, off, errInvalidName
				}
			}

			name = append(name, msg[currOff:endOff]...)
			name = append(name, '.')
			currOff = endOff
		case 0xC0: // Pointer
			if currOff >= len(msg) {
				return nil, off, errInvalidPtr
			}
			c1 := msg[currOff]
			currOff++
			if ptr == 0 {
				newOff = currOff
			}
			// Don't follow too many pointers, maybe there's a loop.
			if ptr++; ptr > 10 {
				return nil, off, errTooManyPtr
			}
			currOff = (c^0xC0)<<8 | int(c1)
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return nil, off, errReserved
		}
	}
	if len(name) == 0 {
		name = append(name, '.')
	}
	if len(name) > nonEncodedNameMax {
		return nil, off, errNameTooLong
	}

	if ptr == 0 {
		newOff = currOff
	}
	return copyBuf(name), newOff, nil
}

// copided and modified from dnsmessage
func decompressName(msg []byte, off int) (*pool.Buffer, int, error) {
	// currOff is the current working offset.
	currOff := off

	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

	// ptr is the number of pointers followed.
	var ptr int

	// Name is a slice representation of the name data.
	var buf [255]byte
	name := buf[:0]

Loop:
	for {
		if currOff >= len(msg) {
			return nil, off, errBaseLen
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
				return nil, off, errCalcLen
			}
			if len(name)+1+c > 254 {
				return nil, off, errNameTooLong
			}

			name = append(name, byte(c))
			name = append(name, msg[currOff:endOff]...)
			currOff = endOff
		case 0xC0: // Pointer
			if currOff >= len(msg) {
				return nil, off, errInvalidPtr
			}
			c1 := msg[currOff]
			currOff++
			if ptr == 0 {
				newOff = currOff
			}
			// Don't follow too many pointers, maybe there's a loop.
			if ptr++; ptr > 10 {
				return nil, off, errTooManyPtr
			}
			currOff = (c^0xC0)<<8 | int(c1)
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return nil, off, errReserved
		}
	}

	name = append(name, 0) // Name end.
	if ptr == 0 {
		newOff = currOff
	}
	return copyBuf(name), newOff, nil
}
