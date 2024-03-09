package dnsmsg

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func labelField(s string) [][]byte {
	return bytes.FieldsFunc([]byte(s), func(r rune) bool { return r == '.' })
}

func TestScanner(t *testing.T) {
	r := require.New(t)
	testFn := func(s string) {
		var builder NameBuilder
		err := builder.ParseReadable([]byte(s))
		r.NoError(err)
		n := builder.ToName()

		labels := make([][]byte, 0)

		scanner := NewNameScanner(n)
		for scanner.Scan() {
			labels = append(labels, scanner.Label())
		}
		r.NoError(scanner.Err())

		r.EqualValues(labelField(s), labels)
	}

	testFn(".")
	testFn("a.b")
	testFn("a.a.aaaaaaaaaa.a.a.a.a.a.a.a.a.a.a.b")
}

func TestParse(t *testing.T) {
	r := require.New(t)

	testFn := func(labels [][]byte, expect error) {
		var builder NameBuilder
		err := builder.Parse(labels)
		if err != nil {
			r.ErrorIs(err, expect)
			return
		}

		out, _, err := dns.UnpackDomainName(append(builder.Data(), 0), 0)
		r.NoError(err)
		in := bytes.Join(labels, []byte{'.'})
		r.Equal(dns.Fqdn(string(in)), out)
	}

	testFn(nil, nil) // root
	testFn([][]byte{{}}, errZeroSegLen)
	testFn(labelField("aa.bb.ccc.dddd"), nil)
	testFn([][]byte{make([]byte, 64)}, errSegTooLong)

	longName := [][]byte{
		make([]byte, 63),
		make([]byte, 63),
		make([]byte, 63),
		make([]byte, 63),
	}
	testFn(longName, errNameTooLong)
}

func TestPack(t *testing.T) {
	r := require.New(t)

	var builder NameBuilder
	err := builder.Parse([][]byte{
		[]byte("www"), []byte("google"), []byte("com"),
	})
	r.NoError(err)

	n := builder.ToName()

	m := newCompressionMap()
	defer releaseCompressionMap(m)

	off := 100
	b := make([]byte, 100+n.PackLen()*3)
	for i := 0; i < 3; i++ {
		off, err = n.pack(b, off, m)
		r.NoError(err)
	}
	r.Equal(100+20, off)

	off = 100
	for i := 0; i < 3; i++ {
		var resBuilder NameBuilder
		off, err = resBuilder.unpack(b, off)
		r.NoError(err)
		res := resBuilder.ToName()
		r.Equal(n, res)
	}
}
