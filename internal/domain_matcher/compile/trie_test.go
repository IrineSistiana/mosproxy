package compile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrie(t *testing.T) {
	comma := []byte(",")
	r := require.New(t)

	tree := NewTree()
	add := func(s string, off int64, inherit bool) {
		labels := bytes.Split([]byte(s), comma)
		tree.Add(labels, off, inherit)
	}

	tree.Add(nil, -1, true) // root node
	add("a", 0, true)
	add("a,a", 1, false)
	add("a,a,a", 2, true)
	add("a,a,a,a", 3, false)

	add("b,b,b", 2, true)

	ct, err := tree.Compile()
	r.NoError(err)
	want := func(s string, dataOff int64, lvl int) {
		labels := bytes.Split([]byte(s), []byte{','})
		gotDataOff, gotLvl := ct.Match(labels)
		r.Equal(dataOff, gotDataOff)
		r.Equal(lvl, gotLvl)

		slices.Reverse(labels)
		gotDataOff, gotLvl = ct.MatchReverse(labels)
		r.Equal(dataOff, gotDataOff)
		r.Equal(lvl, gotLvl)
	}
	want("a", 0, 0)
	want("a,z", 0, 0)   // inherited from a0
	want("a,a", 1, 1)   // full match a1
	want("a,a,z", 0, 0) // inherited from a0, ignore a1
	want("a,a,a", 2, 2)
	want("a,a,a,a", 3, 3)   // full match
	want("a,a,a,a,z", 2, 2) // inherited from a2

	want("b,b,b", 2, 2)
	want("b,b,b,b,c", 2, 2)
	want("b,b", -1, -1)
	want("b,b,c", -1, -1)

	want("zzz,zzz,zzz", -1, -1)
}

func Benchmark_Compile(b *testing.B) {
	r := require.New(b)
	
	// Init a list with 100 TLDa and 10000 lvl 2 domains for each TLD.
	// Total 100k.
	list := new(bytes.Buffer)
	for tld := 0; tld < 100; tld++ {
		for sub := 0; sub < 10000; sub++ {
			fmt.Fprintf(list, "%d.%d\n", rand.Int64(), tld)
		}
	}

	b.Run("load tree", func(b *testing.B) {
		r := require.New(b)
		for i := 0; i < b.N; i++ {
			tree := NewTree()
			err := loadDomainList(tree, bytes.NewReader(list.Bytes()))
			r.NoError(err)
		}
	})

	tree := NewTree()
	err := loadDomainList(tree, bytes.NewReader(list.Bytes()))
	r.NoError(err)
	runtime.GC()
	b.Run("compile tree", func(b *testing.B) {
		r := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := tree.Compile()
			r.NoError(err)
		}
	})

	ct, err := tree.Compile()
	r.NoError(err)
	runtime.GC()

	labels := bytes.Split([]byte("000000.10000000.1"), []byte("."))
	slices.Reverse(labels)
	b.Run("match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ct.Match(labels)
		}
	})

	seq := new(bytes.Buffer)
	err = ct.Serialize(seq)
	r.NoError(err)
	runtime.GC()

	b.Run("serialize", func(b *testing.B) {
		r := require.New(b)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			seq := new(bytes.Buffer)
			err = ct.Serialize(seq)
			r.NoError(err)
		}
	})

	b.Run("deserialize", func(b *testing.B) {
		r := require.New(b)
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err = Deserialize(bytes.NewReader(seq.Bytes()))
			r.NoError(err)
		}
	})
}

func loadDomainList(t *Tree, r io.Reader) error {
	s := bufio.NewScanner(r)
	dot := []byte(".")
	for s.Scan() {
		b := s.Bytes()
		bytes.TrimSpace(b)
		labels := bytes.Split(b, dot)
		slices.Reverse(labels)
		err := t.Add(labels, 0, true)
		if err != nil {
			return err
		}
	}
	return s.Err()
}
