package compile

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompiledTree_Serialize(t *testing.T) {
	r := require.New(t)
	tree := NewTree()
	for i := 0; i < 3; i++ {
		for j := 0; j < 5; j++ {
			labels := [][]byte{[]byte(strconv.Itoa(rand.Int())), []byte(strconv.Itoa(j))}
			err := tree.Add(labels, rand.Int64(), rand.IntN(2) > 1)
			r.NoError(err)
		}
	}
	ct, err := tree.Compile()
	r.NoError(err)

	buf := new(bytes.Buffer)
	err = ct.Serialize(buf)
	r.NoError(err)

	gotCt, err := Deserialize(bytes.NewReader(buf.Bytes()))
	r.NoError(err)
	r.Equal(gotCt.nodes, ct.nodes)
	r.Equal(gotCt.idxNodes, ct.idxNodes)
	r.Equal(gotCt.labels, ct.labels)
}

func TestCompiledTree_BadData(t *testing.T) {
	r := require.New(t)
	initTree := func() *CompiledTree {
		tree := NewTree()
		for i := 0; i < 3; i++ {
			for j := 0; j < 5; j++ {
				labels := [][]byte{[]byte(strconv.Itoa(rand.Int())), []byte(strconv.Itoa(j))}
				err := tree.Add(labels, rand.Int64(), rand.IntN(2) > 1)
				r.NoError(err)
			}
		}
		ct, err := tree.Compile()
		r.NoError(err)
		return ct
	}

	ct := initTree()
	buf := new(bytes.Buffer)
	err := ct.Serialize(buf)
	r.NoError(err)
	_, err = Deserialize(bytes.NewReader(buf.Bytes()))
	r.NoError(err)

	wantErr := func(ct *CompiledTree, errType string) {
		buf := new(bytes.Buffer)
		err := ct.Serialize(buf)
		r.NoError(err)

		_, err = Deserialize(bytes.NewReader(buf.Bytes()))
		r.Errorf(err, "err type [%s] must cause an error", errType)
	}

	ct = initTree()
	ct.nodes[0].childIdxSeg.off += int32(len(ct.idxNodes))
	wantErr(ct, "invalid node child seg offset")

	ct = initTree()
	ct.nodes[0].childIdxSeg.l += int32(len(ct.idxNodes))
	wantErr(ct, "invalid node child seg length")

	ct = initTree()
	ct.idxNodes[0].childIdx += int32(len(ct.nodes))
	wantErr(ct, "invalid idx node idx")

	ct = initTree()
	ct.idxNodes[0].labelSeg.off += int32(len(ct.labels))
	wantErr(ct, "invalid idx node label offset")

	ct = initTree()
	ct.idxNodes[0].labelSeg.l += int32(len(ct.labels))
	wantErr(ct, "invalid idx node label length")

	ct = initTree()
	slices.Reverse(ct.idxNodes)
	wantErr(ct, "invalid idx label order")
}
