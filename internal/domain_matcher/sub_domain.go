package domainmatcher

import "github.com/IrineSistiana/mosproxy/internal/dnsmsg"

type DomainMatcher struct {
	root        labelNode
	rootMatched bool // corner case that "."(root) should be matched
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{}
}

func (m *DomainMatcher) Match(n []byte) bool {
	if m.rootMatched {
		return true
	}

	labels := make([][]byte, 0, 16)
	scanner := dnsmsg.NewNameScanner(n)
	for scanner.Scan() {
		labels = append(labels, scanner.Label())
	}
	if scanner.Err() != nil {
		return false
	}

	currentNode := &m.root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child, ok := currentNode.GetChild(label)
		if child == nil {
			// if ok == true, then this label is a leaf and matched.
			// otherwise, not matched,
			return ok
		}
		currentNode = child
	}
	return false
}

func (m *DomainMatcher) Len() int {
	if m.rootMatched {
		return 1
	}
	return m.root.Len()
}

// Add adds labels to the matcher. Empty label will be ignored.
// If no label was given, add will add the root domain. Which
// will match against all domains.
func (m *DomainMatcher) Add(labels [][]byte) {
	if m.rootMatched {
		return
	}

	hasLabel := false
	currentNode := &m.root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if len(label) == 0 {
			continue
		}
		hasLabel = true
		if i == 0 { // is leaf
			currentNode.AddLeaf(label)
		} else {
			child := currentNode.GetOrAddChild(label)
			currentNode = child
		}
	}

	if !hasLabel {
		m.rootMatched = true
		m.root.l = nil
		m.root.s = nil
		return
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
