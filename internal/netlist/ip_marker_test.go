package netlist

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PackUnpackIpMarkerBin(t *testing.T) {
	r := require.New(t)
	l := makeTestList(1024)

	buf := new(bytes.Buffer)
	err := PackIpMarkerBin(buf, l)
	r.NoError(err)

	_, err = UnpackIpMarkerBin(buf)
	r.NoError(err)
}

func makeTestList(size uint64) *List[uint32] {
	l := new(List[uint32])
	l.e = make([]ipRange[uint32], 0, size)

	for i := uint64(0); i < size; i++ {
		r := ipRange[uint32]{
			start: Ipv6{l: i},
			end:   Ipv6{l: i},
		}
		l.e = append(l.e, r)
	}
	return l
}

func Benchmark_Lookup(b *testing.B) {
	l := makeTestList(10 * 1024)
	for i := 0; i < b.N; i++ {
		idx := i % len(l.e)
		_, ok := l.Lookup(l.e[idx].start)
		if !ok {
			b.Fatal()
		}
	}
}
