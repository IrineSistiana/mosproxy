package netlist

import (
	"fmt"
	"net/netip"
	"sort"
)

type List[V any] struct {
	e []ipRange[V]
}

func (l *List[V]) LookupAddr(addr netip.Addr) (_ V, ok bool) {
	if !addr.IsValid() {
		return
	}
	return l.Lookup(addr2Ipv6(addr))
}

func (l *List[V]) Lookup(ip Ipv6) (_ V, ok bool) {
	i := sort.Search(len(l.e), func(i int) bool {
		return ip.cmp(l.e[i].start) < 0
	})
	if i == 0 {
		return
	}
	return l.e[i-1].contains(ip)
}

func (l *List[V]) Len() int {
	return len(l.e)
}

// Out of range idx will cause runtime panic
func (l *List[V]) Idx(i int) (start, end Ipv6, v V) {
	r := l.e[i]
	return r.start, r.end, r.v
}

type ListBuilder[V any] struct {
	b []ipRange[V]
}

func NewBuilder[V any](initCap int) *ListBuilder[V] {
	return &ListBuilder[V]{
		b: make([]ipRange[V], 0, initCap),
	}
}

// Add returns false if addrs are invalid. Or their range is invalid (start < end).
func (b *ListBuilder[V]) Add(start, end netip.Addr, v V) (ok bool) {
	if !start.IsValid() || !end.IsValid() {
		return false
	}
	r := ipRange[V]{
		start: addr2Ipv6(start),
		end:   addr2Ipv6(end),
		v:     v,
	}
	if r.start.cmp(r.end) > 0 {
		return false // invalid range, start is greater than end.
	}
	b.b = append(b.b, r)
	return true
}

type ipRange[V any] struct {
	v V

	start Ipv6
	end   Ipv6
}

func (r *ipRange[V]) contains(ip Ipv6) (_ V, _ bool) {
	if r.start.cmp(ip) <= 0 && ip.cmp(r.end) <= 0 {
		return r.v, true
	}
	return
}

// Build the list. If no error, the returned List will take the ownership
// of the builder memory. So, Build should only be called once.
func (b *ListBuilder[V]) Build() (*List[V], error) {
	rs := b.b
	sort.Slice(rs, func(i, j int) bool {
		return rs[i].start.cmp(rs[j].start) < 0
	})

	// overlaps?
	for i := 0; i < len(rs)-1; i++ {
		if rs[i].end.cmp(rs[i+1].start) >= 0 {
			return nil, fmt.Errorf("overlapped ranges, %s-%s %s-%s",
				rs[i].start,
				rs[i].end,
				rs[i+1].start,
				rs[i+1].end,
			)
		}
	}
	return &List[V]{
		e: rs,
	}, nil
}
