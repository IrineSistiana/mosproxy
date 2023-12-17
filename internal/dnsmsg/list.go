package dnsmsg

import "sync"

type List[V any] struct {
	noCopy

	l          int
	head, tail *node
}

func (l *List[V]) Add(v V) {
	n := newNode()
	n.v = v
	if l.tail != nil {
		l.tail.next = n
		n.prev = l.tail
		l.tail = n
	} else { // empty set
		l.head = n
		l.tail = n
	}
	l.l++
}

// Once remove is called, n MUST not be used again.
func (l *List[V]) Remove(n *Node[V]) {
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		l.tail = n.prev
	}
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		l.head = n.next
	}
	releaseNode((*node)(n))
	l.l--
}

func (l *List[V]) Len() int { return l.l }

func (l *List[V]) Head() *Node[V] {
	return (*Node[V])(l.head)
}

func (l *List[V]) Tail() *Node[V] {
	return (*Node[V])(l.tail)
}

type Node[V any] node

func (n *Node[V]) Value() V {
	return n.v.(V)
}

func (n *Node[V]) Prev() *Node[V] {
	return (*Node[V])(n.prev)
}

func (n *Node[V]) Next() *Node[V] {
	return (*Node[V])(n.next)
}

type node struct {
	v          any
	prev, next *node
}

var nodePool = sync.Pool{
	New: func() any { return new(node) },
}

func newNode() *node {
	return nodePool.Get().(*node)
}

func releaseNode(n *node) {
	*n = node{}
	nodePool.Put(n)
}
