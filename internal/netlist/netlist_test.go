package netlist

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Netlist(t *testing.T) {
	r := require.New(t)

	add := func(start, end string, v int, b *ListBuilder[int]) {
		startIp := netip.MustParseAddr(start)
		endIp := netip.MustParseAddr(end)
		ok := b.Add(startIp, endIp, v)
		r.True(ok)
	}

	b := NewBuilder[int](0)
	add("0.0.0.0", "0.0.0.4", 1, b) // overlap
	add("0.0.0.4", "0.0.0.5", 1, b)
	l, err := b.Build()
	r.Nil(l)
	r.Error(err)

	b = NewBuilder[int](0)
	add("0.0.0.0", "0.0.0.1", 1, b)
	add("0.0.0.100", "0.0.0.101", 1, b) // overlap
	add("0.0.0.2", "0.0.0.5", 1, b)
	add("0.0.0.95", "0.0.0.100", 1, b) // overlap
	l, err = b.Build()
	r.Nil(l)
	r.Error(err)

	// contain test
	b = NewBuilder[int](0)
	add("0.0.0.0", "0.0.0.4", 1, b)
	add("0.0.0.5", "0.0.0.6", 2, b)
	add("0.0.0.7", "0.0.0.8", 3, b)
	l, err = b.Build()
	r.NoError(err)
	r.NotNil(l)

	ipf := func(s string) Ipv6 {
		return addr2Ipv6(netip.MustParseAddr(s))
	}

	v, ok := l.Lookup(ipf("0.0.0.1")) // matched
	r.True(ok)
	r.Equal(1, v)
	v, ok = l.Lookup(ipf("0.0.0.8")) // matched
	r.True(ok)
	r.Equal(3, v)
	v, ok = l.Lookup(ipf("0.0.0.10")) // not matched
	r.Equal(0, v)
	r.False(ok)
}
