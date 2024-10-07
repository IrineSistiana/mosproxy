package domainmatcher

import (
	"errors"
	"math"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

var (
	errTooManyNodes = errors.New("too many nodes")
)

type tree struct {
	root        node
	assignedIdx int32
}

func newTree() *tree {
	return &tree{}
}

func (t *tree) Add(name dnsmsg.Name, dataOff int64, inherit bool) error {
	labels := name.Labels()
	curNode := &t.root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
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

func (t *tree) newNode() (*node, error) {
	if t.assignedIdx >= math.MaxInt32-1 {
		return nil, errTooManyNodes
	}
	t.assignedIdx++
	n := &node{
		idx: t.assignedIdx,
	}
	return n, nil
}

type node struct {
	idx int32

	hasData  bool
	inherit  bool
	dataOff  int64
	children map[string]*node
}
