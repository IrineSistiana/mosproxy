package netlist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/klauspost/compress/gzip"
)

// TODO: Remove this file (ip marker bin file)
var ipMarkerBinHeader = [...]byte{226, 3, 152, 238, 135, 152, 0, 0} // Use latest bytes as version?

func SaveIpMarkerBin(fp string, l *List[uint32]) error {
	f, err := os.Create(fp)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 16*1024)
	err = PackIpMarkerBin(w, l)
	if err != nil {
		return err
	}
	return w.Flush()
}

func LoadIpMarkerBin(fp string) (*List[uint32], error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return UnpackIpMarkerBin(f)
}

func UnpackIpMarkerBin(r io.Reader) (*List[uint32], error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip header, %w", err)
	}
	if !bytes.Equal(zr.Extra, ipMarkerBinHeader[:]) {
		return nil, errors.New("not a ip marker data file")
	}

	l, err := UnpackIpMarker(zr)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack data, %w", err)
	}
	if err := zr.Close(); err != nil { // invalid check sum
		return nil, err
	}
	return l, nil
}

func PackIpMarkerBin(w io.Writer, list *List[uint32]) error {
	zw := gzip.NewWriter(w)
	zw.Extra = ipMarkerBinHeader[:]
	err := PackIpMarker(list, zw)
	if err != nil {
		return fmt.Errorf("failed to write list, %w", err)
	}
	return zw.Close()
}

func UnpackIpMarker(r io.Reader) (*List[uint32], error) {
	// read length header
	b := make([]byte, 8)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, fmt.Errorf("failed to read header, %w", err)
	}
	u64 := binary.BigEndian.Uint64(b)
	if u64 > math.MaxInt {
		return nil, errors.New("entry length overflowed")
	}
	l := int(u64)
	list := &List[uint32]{
		e: make([]ipRange[uint32], l),
	}
	b = make([]byte, 36)
	e := list.e
	for i := range e {
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, fmt.Errorf("failed to entry #%d, %w", i, err)
		}
		e[i].start.h = binary.BigEndian.Uint64(b[0:])
		e[i].start.l = binary.BigEndian.Uint64(b[8:])
		e[i].end.h = binary.BigEndian.Uint64(b[16:])
		e[i].end.l = binary.BigEndian.Uint64(b[24:])
		e[i].v = binary.BigEndian.Uint32(b[32:])
	}
	return list, nil
}

func PackIpMarker(m *List[uint32], w io.Writer) error {
	b := make([]byte, 36)
	// write 8 bytes length header
	binary.BigEndian.PutUint64(b, uint64(len(m.e)))
	_, err := w.Write(b[:8])
	if err != nil {
		return err
	}

	e := m.e
	for i := range e {
		binary.BigEndian.PutUint64(b, e[i].start.h)
		binary.BigEndian.PutUint64(b[8:], e[i].start.l)
		binary.BigEndian.PutUint64(b[16:], e[i].end.h)
		binary.BigEndian.PutUint64(b[24:], e[i].end.l)
		binary.BigEndian.PutUint32(b[32:], e[i].v)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}
