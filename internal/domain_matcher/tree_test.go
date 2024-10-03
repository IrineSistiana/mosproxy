package domainmatcher

import (
	"testing"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/stretchr/testify/require"
)

func Test_Tree(t *testing.T) {
	r := require.New(t)

	tree := newTree()
	add := func(s string, off int64, inherit bool) {
		var n dnsmsg.Name
		err := n.Parse(s)
		r.NoError(err)
		tree.Add(n, off, inherit)
	}

	add(".", -1, true) // root node
	add("a", 0, true)
	add("a.a", 1, false)
	add("a.a.a", 2, true)
	add("a.a.a.a", 3, false)

	add("b.b.b", 2, true)

	ct, err := tree.Compile()
	r.NoError(err)
	want := func(s string, dataOff int64, lvl int) {
		var n dnsmsg.Name
		err := n.Parse(s)
		r.NoError(err)
		gotDataOff, gotLvl := ct.Match(n)
		r.Equal(dataOff, gotDataOff, "invalid data")
		r.Equal(lvl, gotLvl, "invalid lvl")
	}
	want("a", 0, 0)         // match a0
	want("z.a", 0, 0)       // inherited from a0
	want("a.a", 1, 1)       // full match a1
	want("z.a.a", 0, 0)     // inherited from a0, ignore a1
	want("a.a.a", 2, 2)     // match a2
	want("a.a.a.a", 3, 3)   // full match a3
	want("z.a.a.a.a", 2, 2) // inherited from a2, ignore a3

	want("b.b.b", 2, 2)     // match b2
	want("c.b.b.b.b", 2, 2) // inherited from b2
	want("b.b", -1, -1)     // inherited from root
	want("c.b.b", -1, -1)   // inherited from root

	want("zzz.zzz.zzz", -1, -1) // inherited from root
}
