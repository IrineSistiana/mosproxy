package compile

import (
	"bytes"
	"errors"
	"math"
	"slices"
)

var (
	errLabelSectionOverflowed = errors.New("label section overflowed")
	errIndexSectionOverflowed = errors.New("index section overflowed")
)

type segAddr struct {
	off, l int32
}

type compiledNode struct {
	childIdxSeg segAddr
	dataOff     int64
	stat        uint8
}

const (
	statHasData uint8 = 1
	statInherit uint8 = 1 << 1
)

type idxNode struct {
	labelSeg segAddr
	childIdx int32
}

type CompiledTree struct {
	nodes    []compiledNode
	idxNodes []idxNode
	labels   []byte
}

func (t *Tree) compile() (*CompiledTree, error) {
	e := new(CompiledTree)
	e.nodes = make([]compiledNode, t.assignedIdx+1)
	e.compileNodes(&t.root)

	labelCache := make(map[string]segAddr)
	err := e.buildIdx(&t.root, labelCache)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (e *CompiledTree) compileNodes(n *node) {
	cn := &e.nodes[n.idx]
	if n.hasData {
		cn.stat |= statHasData
		cn.dataOff = n.dataOff
		if n.inherit {
			cn.stat |= statInherit
		}
	}

	for _, child := range n.children {
		e.compileNodes(child)
	}
}

func (e *CompiledTree) buildIdx(n *node, labelCache map[string]segAddr) error {
	cn := &e.nodes[n.idx]

	if t := len(e.idxNodes) + len(n.children); t > math.MaxInt32 || t < 0 {
		return errIndexSectionOverflowed
	}

	cn.childIdxSeg = segAddr{off: int32(len(e.idxNodes)), l: int32(len(n.children))}
	for label, child := range n.children {
		var ie idxNode
		ie.childIdx = child.idx

		var ok bool
		if ie.labelSeg, ok = labelCache[label]; !ok {
			ie.labelSeg, e.labels, ok = append32bs(e.labels, label)
			if !ok {
				return errLabelSectionOverflowed
			}
		}
		e.idxNodes = append(e.idxNodes, ie)
	}
	slices.SortFunc(seg(e.idxNodes, cn.childIdxSeg), func(a, b idxNode) int {
		return bytes.Compare(seg(e.labels, a.labelSeg), seg(e.labels, b.labelSeg))
	})

	for _, child := range n.children {
		err := e.buildIdx(child, labelCache)
		if err != nil {
			return err
		}
	}
	return nil
}

// return nil if idx.off < 0
func seg[T any](s []T, idx segAddr) []T {
	if idx.off < 0 {
		return nil
	}
	return s[idx.off : idx.off+idx.l]
}

// Match returns the closest node from tree and its level .
// e.g. For tree that contains "a,b,c" and labels are "a,b,c,d", it returns
// the dataOff at node "c" and lvl==2.
// If matched the root node, lvl==-1.
// If no match, return -2.
func (e *CompiledTree) Match(labels [][]byte) (dataOff int64, lvl int) {
	return e.match(labels, false)
}

// Same as Match but match the labels in a reversed order.
func (e *CompiledTree) MatchReverse(labels [][]byte) (dataOff int64, lvl int) {
	return e.match(labels, true)
}

func (e *CompiledTree) match(labels [][]byte, reverse bool) (dataOff int64, lvl int) {
	lvl = -2
	if len(e.nodes) == 0 { // empty tree
		return
	}

	curNode := e.nodes[0]
	if curNode.stat&statHasData > 0 {
		if curNode.stat&statInherit > 0 {
			dataOff = curNode.dataOff
			lvl = -1
		} else {
			lvl = -1
			if lvl == len(labels)-1 { // full match
				dataOff = curNode.dataOff
				return
			}
		}
	}

	tail := len(labels) - 1
	for i, label := range labels {
		if reverse {
			label = labels[tail-i]
		} else {
			label = labels[i]
		}
		idxSeg := seg(e.idxNodes, curNode.childIdxSeg)
		elemIdx := e.binarySearchIdx(idxSeg, label)
		if elemIdx < 0 {
			return
		}
		childIdx := idxSeg[elemIdx].childIdx
		curNode = e.nodes[childIdx]
		if curNode.stat&statHasData > 0 {
			if curNode.stat&statInherit > 0 {
				dataOff = curNode.dataOff
				lvl = i
			} else {
				if i == len(labels)-1 { // full match
					dataOff = curNode.dataOff
					lvl = i
					return
				}
			}
		}
	}
	return
}

// Helper func. Returns the total number nodes that contain data.
// Note: Takes O(n) time.
func (e *CompiledTree) Len() int {
	s := 0
	for i := range e.nodes {
		if e.nodes[i].stat&statHasData > 0 {
			s++
		}
	}
	return s
}

// Modified form slice.BinarySearch.
// If target was found, return the index of the target, otherwise return
// -1.
func (e *CompiledTree) binarySearchIdx(s []idxNode, target []byte) int {
	n := len(s)
	// Define cmp(x[-1], target) < 0 and cmp(x[n], target) >= 0 .
	// Invariant: cmp(x[i - 1], target) < 0, cmp(x[j], target) >= 0.
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if bytes.Compare(seg(e.labels, s[h].labelSeg), target) < 0 {
			i = h + 1 // preserves cmp(x[i - 1], target) < 0
		} else {
			j = h // preserves cmp(x[j], target) >= 0
		}
	}
	// i == j, cmp(x[i-1], target) < 0, and cmp(x[j], target) (= cmp(x[i], target)) >= 0  =>  answer is i.
	if i < n && bytes.Equal(seg(e.labels, s[i].labelSeg), target) {
		return i
	}
	return -1
}
