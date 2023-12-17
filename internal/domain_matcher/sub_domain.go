package domainmatcher

import (
	"bytes"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type DomainMatcher struct {
	root        labelNode
	rootMatched bool // corner case that "."(root) should be matched
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{}
}

func (m *DomainMatcher) MatchString(n string) bool {
	b := normDomainStr(n)
	defer pool.ReleaseBuf(b)
	return m.match(b.B())
}
func (m *DomainMatcher) Match(n []byte) bool {
	b := normDomain(n)
	defer pool.ReleaseBuf(b)
	return m.match(b.B())
}

func (m *DomainMatcher) match(n []byte) bool {
	if m.rootMatched {
		return true
	}
	off := len(n)
	currentNode := &m.root
	for off > 0 {
		prevDot := bytes.LastIndexByte(n[:off], '.')
		label := n[prevDot+1 : off]
		child, ok := currentNode.GetChild(label)
		if child == nil {
			// if ok == true, then this label is a leaf and matched.
			// otherwise, not matched,
			return ok
		}
		currentNode = child
		off = prevDot
	}
	return false
}

func (m *DomainMatcher) Len() int {
	if m.rootMatched {
		return 1
	}
	return m.root.Len()
}

func (m *DomainMatcher) Add(s []byte) {
	b := normDomain(s)
	defer pool.ReleaseBuf(b)
	m.add(b.B())
}

func (m *DomainMatcher) add(n []byte) {
	if m.rootMatched {
		return
	}
	if len(n) == 0 {
		m.rootMatched = true
		m.root.l = nil
		m.root.s = nil
		return
	}

	off := len(n)
	currentNode := &m.root
	for off > 0 {
		prevDot := bytes.LastIndexByte(n[:off], '.')
		label := n[prevDot+1 : off]
		if prevDot == -1 { // is leaf
			currentNode.AddLeaf(label)
		} else {
			child := currentNode.GetOrAddChild(label)
			currentNode = child
		}
		off = prevDot
	}
}

// labelNode can store dns labels.
type labelNode struct {
	// lazy init
	s map[[24]byte]*labelNode
	l map[string]*labelNode
}

func (n *labelNode) AddLeaf(label []byte) {
	l := len(label)
	if l <= 24 {
		if n.s == nil {
			n.s = make(map[[24]byte]*labelNode)
		}
		var key [24]byte
		copy(key[:], label)
		n.s[key] = nil
	} else {
		if n.l == nil {
			n.l = make(map[string]*labelNode)
		}
		n.l[string(label)] = nil
	}
}

func (n *labelNode) GetOrAddChild(label []byte) *labelNode {
	l := len(label)
	if l <= 24 {
		var key [24]byte
		copy(key[:], label)
		if child := n.s[key]; child != nil {
			return child
		}
		if n.s == nil {
			n.s = make(map[[24]byte]*labelNode)
		}
		child := new(labelNode)
		n.s[key] = child
		return child
	}

	if child := n.l[string(label)]; child != nil { // this convert does not allocate
		return child
	}
	if n.l == nil {
		n.l = make(map[string]*labelNode)
	}
	child := new(labelNode)
	n.l[string(label)] = child // this convert only runs/allocates once
	return child
}

func (n *labelNode) GetChild(label []byte) (child *labelNode, ok bool) {
	l := len(label)
	if l <= 24 {
		var key [24]byte
		copy(key[:], label)
		child, ok = n.s[key]
		return
	}
	child, ok = n.l[string(label)]
	return
}

func (n *labelNode) Len() int {
	l := 0
	for _, c := range n.s {
		if c == nil {
			l++
		} else {
			l += c.Len()
		}
	}
	for _, c := range n.l {
		if c == nil {
			l++
		} else {
			l += c.Len()
		}
	}
	return l
}
