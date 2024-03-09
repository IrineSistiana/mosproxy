package domainmatcher

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/stretchr/testify/require"
)

func Test_SubdomainMatcher(t *testing.T) {
	r := require.New(t)

	m := NewDomainMatcher()
	add := func(s string) {
		labels := bytes.FieldsFunc([]byte(s), func(r rune) bool { return r == '.' })
		m.Add(labels)
	}
	match := func(s string) bool {
		var name dnsmsg.NameBuilder
		err := name.ParseReadable([]byte(s))
		r.NoError(err)
		res := m.Match(name.Data())
		return res
	}

	add("com")
	add("abc.def")
	r.Equal(m.Len(), 2)

	r.True(match("com"))
	r.False(match("def"))
	r.True(match("a.b.c.com"))
	r.False(match("com.a"))

	r.True(match("abc.def"))
	r.True(match("123.abc.def"))

	r.False(match("123.def"))

	add("a.root")
	add("b.root")
	add("c.root")
	r.Equal(m.Len(), 5)

	add("root") // remove all sub domains
	r.Equal(m.Len(), 3)

	add("")
	r.Equal(m.Len(), 1)
	r.True(match("1234556"))
}

func Benchmark_sub_domain(b *testing.B) {
	randNames := make([][][]byte, 0, 10000)
	for i := 0; i < 10000; i++ {
		name := make([][]byte, 0, 3)
		for j := 0; j < 3; j++ {
			label := make([]byte, 8)
			rand.Read(label)
			name = append(name, label)
		}
		randNames = append(randNames, name)
	}

	m := NewDomainMatcher()
	for _, name := range randNames {
		m.Add(name)
	}

	matchNames := make([][]byte, 0, len(randNames))
	for _, name := range randNames {
		var builder dnsmsg.NameBuilder

		err := builder.Parse(name)
		if err != nil {
			b.Fatal(err)
		}
		matchNames = append(matchNames, builder.Data())
	}
	if m.Len() != 10000 {
		b.Fatal("unexpected matcher size")
	}

	runtime.GC()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		name := matchNames[i%len(matchNames)]
		ok := m.Match(name)
		if !ok {
			b.Fatal("unexpected matcher result")
		}
	}
}
