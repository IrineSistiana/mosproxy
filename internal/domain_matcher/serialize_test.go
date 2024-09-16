package domainmatcher

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Serialize(t *testing.T) {
	r := require.New(t)
	initM := func() *Matcher {
		list := new(bytes.Buffer)
		for tld := 0; tld < 10; tld++ {
			for sub := 0; sub < 10; sub++ {
				fmt.Fprintf(list, "%d.%d\n", rand.Int64(), tld)
				fmt.Fprintf(list, "regexp:^%d\\.%d$\n", rand.Int64(), tld)
			}
		}
		loader := NewLoader()
		err := loader.LoadRulesFromReader(list)
		r.NoError(err)
		m, err := loader.Compile()
		r.NoError(err)
		return m
	}

	buf := new(bytes.Buffer)
	m := initM()
	err := m.Serialize(buf)
	r.NoError(err)

	gotM, err := Deserialize(bytes.NewReader(buf.Bytes()))
	r.NoError(err)
	r.Equal(m.ct, gotM.ct)
	for i, re := range m.re {
		r.Equal(re.String(), gotM.re[i].String())
	}

	t.Run("bad data", func(t *testing.T) {
		wantErr := func(m *Matcher, errType string) {
			buf := new(bytes.Buffer)
			err := m.Serialize(buf) // no check in Serialize
			r.NoError(err)

			_, err = Deserialize(bytes.NewReader(buf.Bytes()))
			r.Errorf(err, "err type [%s] must cause an error", errType)
		}

		m := initM()
		ct := m.ct
		ct.nodes[0].childIdxSeg.off += int32(len(ct.idxNodes))
		wantErr(m, "invalid node child seg offset")

		m = initM()
		ct = m.ct
		ct.nodes[0].childIdxSeg.l += int32(len(ct.idxNodes))
		wantErr(m, "invalid node child seg length")

		m = initM()
		ct = m.ct
		ct.idxNodes[0].childIdx += int32(len(ct.nodes))
		wantErr(m, "invalid idx node idx")

		m = initM()
		ct = m.ct
		ct.idxNodes[0].labelSeg.off += int32(len(ct.labels))
		wantErr(m, "invalid idx node label offset")

		m = initM()
		ct = m.ct
		ct.idxNodes[0].labelSeg.l += int32(len(ct.labels))
		wantErr(m, "invalid idx node label length")

		m = initM()
		ct = m.ct
		slices.Reverse(ct.idxNodes)
		wantErr(m, "invalid idx label order")
	})
}
