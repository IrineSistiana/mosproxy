package domainmatcher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"

	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/klauspost/compress/zstd"
)

var (
	errInvalidPreface   = errors.New("invalid preface")
	errUInt31Overflowed = errors.New("uint31 overflowed")
	errUInt16Overflowed = errors.New("uint16 overflowed")
)

const preface = "mosproxy_ct_v2"

func Deserialize(r io.Reader) (*Matcher, error) {
	var buf [len(preface)]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read preface, %w", err)
	}

	if string(buf[:]) != preface {
		return nil, errInvalidPreface
	}

	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to init zstd reader, %w", err)
	}
	defer zr.Close()

	// load body
	m, err := deserializeBody(zr)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize body, %w", err)
	}
	return m, nil
}

func (m *Matcher) Serialize(w io.Writer) (err error) {
	_, err = w.Write([]byte(preface))
	if err != nil {
		return fmt.Errorf("failed to write preface header, %w", err)
	}

	zw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return fmt.Errorf("failed to init zstd writer, %w", err)
	}
	defer func() {
		closeErr := zw.Close()
		if err == nil {
			err = closeErr
		}
	}()

	err = m.serializeBody(zw)
	if err != nil {
		return fmt.Errorf("failed to serialize body, %w", err)
	}
	return nil
}

func (m *Matcher) serializeBody(w io.Writer) error {
	// compile tree
	buf := make([]byte, 17)
	writeUint31 := func(i int) error {
		if i > math.MaxInt32 || i < 0 {
			return errUInt31Overflowed
		}
		binary.BigEndian.PutUint32(buf[:4], uint32(i))
		_, err := w.Write(buf[:4])
		return err
	}
	writeUint16 := func(i int) error {
		if i > math.MaxUint16 || i < 0 {
			return errUInt16Overflowed
		}
		binary.BigEndian.PutUint16(buf[:2], uint16(i))
		_, err := w.Write(buf[:2])
		return err
	}

	// length header
	err := writeUint31(len(m.ct.nodes))
	if err != nil {
		return fmt.Errorf("failed to write node section header, %w", err)
	}
	err = writeUint31(len(m.ct.idxNodes))
	if err != nil {
		return fmt.Errorf("failed to write index section header, %w", err)
	}
	err = writeUint31(len(m.ct.labels))
	if err != nil {
		return fmt.Errorf("failed to write label section header, %w", err)
	}
	err = writeUint31(len(m.re))
	if err != nil {
		return fmt.Errorf("failed to write regexp section header, %w", err)
	}

	// node
	for i := range m.ct.nodes {
		node := &m.ct.nodes[i]
		binary.BigEndian.PutUint32(buf[0:4], uint32(node.childIdxSeg.off))
		binary.BigEndian.PutUint32(buf[4:8], uint32(node.childIdxSeg.l))
		binary.BigEndian.PutUint64(buf[8:16], uint64(node.dataOff))
		buf[16] = node.stat
		_, err := w.Write(buf[:17])
		if err != nil {
			return fmt.Errorf("failed to write node #%d, %w", i, err)
		}
	}

	// idx
	for i := range m.ct.idxNodes {
		idx := &m.ct.idxNodes[i]
		binary.BigEndian.PutUint32(buf[:4], uint32(idx.labelSeg.off))
		binary.BigEndian.PutUint32(buf[4:8], uint32(idx.labelSeg.l))
		binary.BigEndian.PutUint32(buf[8:12], uint32(idx.childIdx))
		_, err := w.Write(buf[:12])
		if err != nil {
			return fmt.Errorf("failed to write index node #%d, %w", i, err)
		}
	}

	// labels
	_, err = w.Write(m.ct.labels)
	if err != nil {
		return fmt.Errorf("failed to write label section, %w", err)
	}

	// regexp
	for i, re := range m.re {
		expr := re.String()
		err := writeUint16(len(expr))
		if err != nil {
			return fmt.Errorf("failed to write regexp #%d length, %w", i, err)
		}
		_, err = w.Write(utils.Str2BytesUnsafe(expr))
		if err != nil {
			return fmt.Errorf("failed to write regexp #%d, %w", i, err)
		}
	}

	return nil
}

func deserializeBody(r io.Reader) (*Matcher, error) {
	var buf [17]byte

	readUint31 := func() (int32, error) {
		_, err := r.Read(buf[:4])
		if err != nil {
			return 0, err
		}
		i := int32(binary.BigEndian.Uint32(buf[:4]))
		if i < 0 {
			return 0, errUInt31Overflowed
		}
		return i, nil
	}
	readUint16 := func() (uint16, error) {
		_, err := r.Read(buf[:2])
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(buf[:2]), nil
	}
	sa := func(b []byte) (sa segAddr) {
		sa.off = int32(binary.BigEndian.Uint32(b[0:4]))
		sa.l = int32(binary.BigEndian.Uint32(b[4:8]))
		return
	}

	nodeLength, err := readUint31()
	if err != nil {
		return nil, fmt.Errorf("failed to read nodes length, %w", err)
	}
	idxLength, err := readUint31()
	if err != nil {
		return nil, fmt.Errorf("failed to read idx length, %w", err)
	}
	labelLength, err := readUint31()
	if err != nil {
		return nil, fmt.Errorf("failed to read labels length, %w", err)
	}
	regexpLength, err := readUint31()
	if err != nil {
		return nil, fmt.Errorf("failed to read regexp section length, %w", err)
	}

	// compiled tree
	ct := new(compiledTree)

	// nodes
	readNode := func() (node compiledNode, err error) {
		_, err = io.ReadFull(r, buf[:17])
		if err != nil {
			return
		}
		node.childIdxSeg = sa(buf[0:8])
		node.dataOff = int64(binary.BigEndian.Uint64(buf[8:16]))
		node.stat = buf[16]
		return
	}
	for i := int32(0); i < nodeLength; i++ {
		node, err := readNode()
		if err != nil {
			return nil, fmt.Errorf("failed to read nodes #%d, %w", i, err)
		}
		ct.nodes = append(ct.nodes, node)
	}

	// idx
	readIdx := func() (idx idxNode, err error) {
		_, err = io.ReadFull(r, buf[:12])
		if err != nil {
			return
		}

		idx.labelSeg = sa(buf[0:8])
		idx.childIdx = int32(binary.BigEndian.Uint32(buf[8:12]))
		return
	}
	for i := int32(0); i < idxLength; i++ {
		idx, err := readIdx()
		if err != nil {
			return nil, fmt.Errorf("failed to read idx segment #%d, %w", i, err)
		}
		ct.idxNodes = append(ct.idxNodes, idx)
	}

	// labels
	if labelLength > 0 {
		labels, err := io.ReadAll(io.LimitReader(r, int64(labelLength)))
		if err != nil {
			return nil, fmt.Errorf("failed to read labels, %w", err)
		}
		ct.labels = labels
	}

	// pointers validation
	for i := range ct.nodes {
		node := &ct.nodes[i]
		// check node idx segment addr
		idxSa := node.childIdxSeg
		if !validSegAddr(idxSa, idxLength) {
			return nil, fmt.Errorf("invalid idx seg addr at node #%d", i)
		}

		idxSeg := seg(ct.idxNodes, idxSa)
		for j := range idxSeg {
			e := &idxSeg[j]
			if nodeIdx := e.childIdx; nodeIdx < 0 || nodeIdx >= nodeLength { // node idx must in range
				return nil, fmt.Errorf("invalid child idx at node #%d idx #%d", i, j)
			}
			if !validSegAddr(e.labelSeg, labelLength) {
				return nil, fmt.Errorf("invalid idx label seg addr at node #%d idx #%d", i, j)
			}
			if j > 0 {
				// labels must in ascending order
				prevLabel := seg(ct.labels, idxSeg[j-1].labelSeg)
				curLabel := seg(ct.labels, e.labelSeg)
				if bytes.Compare(prevLabel, curLabel) != -1 {
					return nil, fmt.Errorf("invalid label order at node #%d idx #%d", i, j)
				}
			}
		}
	}

	// regexp
	readRegexp := func() (*regexp.Regexp, error) {
		l, err := readUint16()
		if err != nil {
			return nil, fmt.Errorf("failed to read regexp length, %w", err)
		}
		buf2 := make([]byte, l)
		_, err = io.ReadFull(r, buf2)
		if err != nil {
			return nil, fmt.Errorf("failed to read regexp body, %w", err)
		}
		expr := utils.Bytes2StrUnsafe(buf2)
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid regexp, %w", err)
		}
		return re, nil
	}
	res := make([]*regexp.Regexp, 0)
	for i := int32(0); i < regexpLength; i++ {
		re, err := readRegexp()
		if err != nil {
			return nil, fmt.Errorf("failed to read regexp #%d, %w", i, err)
		}
		res = append(res, re)
	}

	return &Matcher{ct: ct, re: res}, nil
}
