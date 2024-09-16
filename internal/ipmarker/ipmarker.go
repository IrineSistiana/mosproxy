package ipmarker

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/netlist"
	"github.com/IrineSistiana/mosproxy/internal/utils"
)

type IpMarker struct {
	l          *netlist.List[int]
	marks      []string
}

func (m *IpMarker) Mark(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	idx, ok := m.l.LookupAddr(addr)
	if !ok {
		return ""
	}
	return m.marks[idx]
}

func (m *IpMarker) IpLen() int {
	return m.l.Len()
}

func (m *IpMarker) MarkLen() int {
	return len(m.marks)
}

func cut(s []byte, i byte) ([]byte, []byte, bool) {
	if i := bytes.IndexByte(s, i); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, nil, false
}

// format: start,end,mark
// # comment
func LoadIpMarkerFromReader(r io.Reader) (*IpMarker, error) {
	listBuilder := netlist.NewBuilder[int](0)
	labelIndexes := make(map[string]int)
	labels := make([]string, 0)

	parseLine := func(b []byte) error {
		t, b, ok := cut(b, ',')
		if !ok {
			return errors.New("missing first comma")
		}
		start, err := netip.ParseAddr(utils.Bytes2StrUnsafe(t))
		if err != nil {
			return fmt.Errorf("invalid start addr, %w", err)
		}
		t, b, ok = cut(b, ',')
		if !ok {
			return errors.New("missing second comma")
		}
		end, err := netip.ParseAddr(utils.Bytes2StrUnsafe(t))
		if err != nil {
			return fmt.Errorf("invalid end addr, %w", err)
		}

		idx, ok := labelIndexes[string(b)]
		if !ok {
			label := string(b)
			labels = append(labels, label)
			idx = len(labels) - 1
			labelIndexes[label] = idx
		}

		if ok := listBuilder.Add(start, end, idx); !ok {
			return fmt.Errorf("invalid range %s-%s", start, end)
		}

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
	l, err := listBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build ip list, %w", err)
	}
	return &IpMarker{
		l:     l,
		marks: labels,
	}, nil
}
