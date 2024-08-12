package compile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/klauspost/compress/zstd"
)

var (
	errInvalidPreface   = errors.New("invalid preface")
	errUInt31Overflowed = errors.New("uint31 overflowed")
)

const preface = "mosproxy_ct_v1"

func (ct *CompiledTree) Serialize(w io.Writer) (err error) {
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

	buf := make([]byte, 17)
	writeUint31 := func(i int) error {
		if i > math.MaxInt32 || i < 0 {
			return errUInt31Overflowed
		}
		binary.BigEndian.PutUint32(buf[:4], uint32(i))
		_, err := zw.Write(buf[:4])
		return err
	}

	// length header
	err = writeUint31(len(ct.nodes))
	if err != nil {
		return fmt.Errorf("failed to write node section header, %w", err)
	}
	err = writeUint31(len(ct.idxNodes))
	if err != nil {
		return fmt.Errorf("failed to write index section header, %w", err)
	}
	err = writeUint31(len(ct.labels))
	if err != nil {
		return fmt.Errorf("failed to write label section header, %w", err)
	}

	// node
	for i := range ct.nodes {
		node := &ct.nodes[i]
		binary.BigEndian.PutUint32(buf[0:4], uint32(node.childIdxSeg.off))
		binary.BigEndian.PutUint32(buf[4:8], uint32(node.childIdxSeg.l))
		binary.BigEndian.PutUint64(buf[8:16], uint64(node.dataOff))
		buf[16] = node.stat
		_, err := zw.Write(buf[:17])
		if err != nil {
			return fmt.Errorf("failed to write node #%d, %w", i, err)
		}
	}

	// idx
	for i := range ct.idxNodes {
		idx := &ct.idxNodes[i]
		binary.BigEndian.PutUint32(buf[:4], uint32(idx.labelSeg.off))
		binary.BigEndian.PutUint32(buf[4:8], uint32(idx.labelSeg.l))
		binary.BigEndian.PutUint32(buf[8:12], uint32(idx.childIdx))
		_, err := zw.Write(buf[:12])
		if err != nil {
			return fmt.Errorf("failed to write index node #%d, %w", i, err)
		}
	}

	// labels
	_, err = zw.Write(ct.labels)
	if err != nil {
		return fmt.Errorf("failed to write label section, %w", err)
	}
	return nil
}

func Deserialize(r io.Reader) (*CompiledTree, error) {
	var buf [17]byte
	_, err := io.ReadFull(r, buf[:len(preface)])
	if err != nil {
		return nil, fmt.Errorf("failed to read preface, %w", err)
	}

	if string(buf[:len(preface)]) != preface {
		return nil, errInvalidPreface
	}

	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to init zstd reader, %w", err)
	}
	defer zr.Close()

	ct := new(CompiledTree)
	readUint31 := func() (int32, error) {
		_, err := zr.Read(buf[:4])
		if err != nil {
			return 0, err
		}
		i := int32(binary.BigEndian.Uint32(buf[:4]))
		if i < 0 {
			return 0, errUInt31Overflowed
		}
		return i, nil
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

	// nodes
	readNode := func() (node compiledNode, err error) {
		_, err = io.ReadFull(zr, buf[:17])
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
		_, err = io.ReadFull(zr, buf[:12])
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
		labels, err := io.ReadAll(io.LimitReader(zr, int64(labelLength)))
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
	return ct, nil
}
