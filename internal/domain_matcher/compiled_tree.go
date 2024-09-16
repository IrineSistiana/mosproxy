package domainmatcher

import (
	"bytes"
	"errors"
	"math"
	"slices"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
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

type compiledTree struct {
	nodes    []compiledNode
	idxNodes []idxNode
	labels   []byte
}

func (t *tree) Compile() (*compiledTree, error) {
	e := new(compiledTree)
	e.nodes = make([]compiledNode, t.assignedIdx+1)
	e.compileNodes(&t.root)

	labelCache := make(map[string]segAddr)
	err := e.buildIdx(&t.root, labelCache)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (e *compiledTree) compileNodes(n *node) {
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

func (e *compiledTree) buildIdx(n *node, labelCache map[string]segAddr) error {
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
func (e *compiledTree) Match(n *dnsmsg.Name) (dataOff int64, lvl int) {
	lvl = -2
	if len(e.nodes) == 0 { // empty tree
		return
	}

	var fm bool // full match
	var fmOff int64
	var fmLvl int

	curNode := e.nodes[0]
	if curNode.stat&statHasData > 0 {
		if curNode.stat&statInherit > 0 {
			dataOff = curNode.dataOff
			lvl = -1
		} else {
			fm = true
			fmOff = curNode.dataOff
			fmLvl = -1
		}
	}

	s := dnsmsg.NewNameScanner(n)
	s.Reverse()
	for i := 0; s.Scan(); i++ {
		// reset fm status
		fm = false
		fmOff = 0
		fmLvl = 0

		idxSeg := seg(e.idxNodes, curNode.childIdxSeg)
		elemIdx := e.binarySearchIdx(idxSeg, s.Label())
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
				fm = true
				fmOff = curNode.dataOff
				fmLvl = i
			}
		}
	}
	if fm {
		return fmOff, fmLvl
	}
	return
}

// Helper func. Returns the total number nodes that contain data.
// Note: Takes O(n) time.
func (e *compiledTree) Len() int {
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
func (e *compiledTree) binarySearchIdx(s []idxNode, target []byte) int {
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
