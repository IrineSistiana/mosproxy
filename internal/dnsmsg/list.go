package dnsmsg

type linkNode struct {
	prev, next Linkable
}

func (n *linkNode) Prev() Linkable {
	return n.prev
}

func (n *linkNode) Next() Linkable {
	return n.next
}

func (n *linkNode) SetPrev(v Linkable) {
	n.prev = v
}

func (n *linkNode) SetNext(v Linkable) {
	n.next = v
}

type Linkable interface {
	Prev() Linkable
	Next() Linkable
	SetPrev(Linkable)
	SetNext(Linkable)
}

type List[V Linkable] struct {
	noCopy

	l          int
	head, tail Linkable
}

func (l *List[V]) Add(v V) {
	if l.tail != nil {
		l.tail.SetNext(v)
		v.SetPrev(l.tail)
		l.tail = v
	} else {
		l.head = v
		l.tail = v
	}
	l.l++
}

func (l *List[V]) Remove(v V) {
	if n := v.Next(); n != nil {
		n.SetPrev(v.Prev())
	} else {
		l.tail = v.Prev()
	}
	if n := v.Prev(); n != nil {
		n.SetNext(v.Next())
	} else {
		l.head = v.Next()
	}
	l.l--
}

func (l *List[V]) Head() (v V) {
	if l.head == nil {
		return
	}
	return l.head.(V)
}

func (l *List[V]) Tail() (v V) {
	if l.tail == nil {
		return
	}
	return l.tail.(V)
}

func (l *List[V]) Len() int {
	return l.l
}

func (l *List[V]) Iter() Iter[V] {
	return Iter[V]{n: l.head}
}

func (l *List[V]) ReverseIter() Iter[V] {
	return Iter[V]{reverse: true, n: l.tail}
}

type Iter[V Linkable] struct {
	reverse bool
	started bool
	n       Linkable
}

func (i *Iter[V]) Next() bool {
	if !i.started {
		i.started = true
		return i.n != nil
	}

	if i.n != nil {
		if i.reverse {
			i.n = i.n.Prev()
		} else {
			i.n = i.n.Next()
		}
		return i.n != nil
	}
	return false
}

func (i *Iter[V]) Value() (n V) {
	if i.n != nil {
		return i.n.(V)
	}
	return
}
