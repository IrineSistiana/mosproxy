package domainmatcher

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/stretchr/testify/require"
)

func TestMixMatcher_Match(t *testing.T) {
	r := require.New(t)

	loader := NewLoader()

	add := func(rule string) {
		err := loader.Add([]byte(rule))
		r.NoError(err)
	}

	add("full:full.FULL.full")

	add("regexp:^full.reg.exp$")
	add("regexp:^reg.exp.prefix")

	add("domain:domain.SUFFIX")
	add("CAP.SUFFIX")

	m, err := loader.Compile()
	r.NoError(err)
	match := func(n string, expect bool) {
		var builder dnsmsg.NameBuilder
		err := builder.ParseReadable([]byte(n))
		r.NoError(err)
		res := m.Match(builder.Data())
		r.Equalf(expect, res, "match [%s]", n)
	}

	match("full.full.full", true)
	match("0.full.full.full", false)

	match("full.reg.exp", true)
	match("full0.reg.exp", false)
	match("reg.exp.prefix", true)
	match("reg.exp.prefix.1.2.3", true)

	match("domain.suffix", true)
	match("domain0.suffix", false)
	match("1.2.3.domain.suffix", true)
	match("123.cap.suffix", true)
}

func Benchmark_Matcher(b *testing.B) {
	// init a domain list with 100 TLDs and 1000 sub domains for each TLD
	const (
		tldN = 100
		l2N  = 1000
	)
	names := make([][][]byte, 0, tldN*l2N)
	for i := 0; i < tldN; i++ {
		for j := 0; j < l2N; j++ {
			names = append(names, [][]byte{[]byte(strconv.Itoa(i)), []byte(strconv.Itoa(j))})
		}
	}

	rules := make([][]byte, 0)
	for _, name := range names {
		rules = append(rules, []byte(fmt.Sprintf("%s.%s", name[0], name[1])))
	}

	b.Run("init", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			l := NewLoader()
			for _, rule := range rules {
				err := l.Add(rule)
				if err != nil {
					b.Fatal(err)
				}
			}
			_, err := l.Compile()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	l := NewLoader()
	for _, rule := range rules {
		err := l.Add(rule)
		if err != nil {
			b.Fatal(err)
		}
	}
	m, err := l.Compile()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("match", func(b *testing.B) {
		matchNames := make([]dnsmsg.Name, 0, len(names))
		for _, name := range names {
			var builder dnsmsg.NameBuilder
			err := builder.Parse(name)
			if err != nil {
				b.Fatal(err)
			}
			matchNames = append(matchNames, builder.ToName())
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
	})
}
