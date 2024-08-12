package compile

import (
	"errors"
	"math"
)

var (
	errTooManyNodes = errors.New("too many nodes")
)

type Tree struct {
	root        node
	assignedIdx int32
}

func NewTree() *Tree {
	return &Tree{}
}

func (t *Tree) Add(labels [][]byte, dataOff int64, inherit bool) error {
	curNode := &t.root
	for _, label := range labels {
		child, ok := curNode.children[string(label)]
		if !ok {
			var err error
			child, err = t.newNode()
			if err != nil {
				return err
			}
			if curNode.children == nil {
				curNode.children = make(map[string]*node)
			}
			curNode.children[string(label)] = child
		}
		curNode = child
	}
	curNode.hasData = true
	curNode.inherit = inherit
	curNode.dataOff = dataOff
	return nil
}

func (t *Tree) newNode() (*node, error) {
	if t.assignedIdx >= math.MaxInt32-1 {
		return nil, errTooManyNodes
	}
	t.assignedIdx++
	n := &node{
		idx: t.assignedIdx,
	}
	return n, nil
}

func (t *Tree) Compile() (*CompiledTree, error) {
	return t.compile()
}

type node struct {
	idx int32

	hasData  bool
	inherit  bool
	dataOff  int64
	children map[string]*node
}
