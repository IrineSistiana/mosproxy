package ipmarker

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/utils"
)

// format: mark,(prefix|"-")[# comment]
// e.g. "asia,22.22.22.0/24" "asia,-"
//
// "-" means remove the ecs.
func LoadMark2PrefixFromReader(r io.Reader) (map[string]netip.Prefix, error) {
	m := make(map[string]netip.Prefix)
	parseLine := func(b []byte) error {
		mark, addrS, ok := cut(b, ',')
		if !ok {
			return errors.New("missing comma")
		}

		var p netip.Prefix
		if string(addrS) != "-" {
			var err error
			p, err = netip.ParsePrefix(utils.Bytes2StrUnsafe(addrS))
			if err != nil {
				return fmt.Errorf("invalid ecs, %w", err)
			}
		}

		_, dup := m[string(mark)]
		if dup {
			return fmt.Errorf("duplicated mark %s", mark)
		}
		m[string(mark)] = p
		return nil
	}

	scanner := bufio.NewScanner(r)
	line := 0
	for scanner.Scan() {
		line++
		b := scanner.Bytes()
		b, _, _ = cut(b, '#')
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			continue
		}

		err := parseLine(b)
		if err != nil {
			return nil, fmt.Errorf("invalid line #%d, %w", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner io error, %w", err)
	}
	return m, nil
}
