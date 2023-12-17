package domainmatcher

import (
	"bufio"
	"bytes"
	"io"
)

func LoadMixMatcherFromReader(m *MixMatcher, r io.Reader) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		b := s.Bytes()
		if i := bytes.IndexByte(b, '#'); i >= 0 {
			b = b[:i]
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			continue
		}
		err := m.Add(b)
		if err != nil {
			return err
		}
	}
	return s.Err()
}
