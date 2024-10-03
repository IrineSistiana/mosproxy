package domainmatcher

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
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
		var name dnsmsg.Name
		err := name.Parse(n)
		r.NoError(err)
		res := m.Match(name)
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

func Benchmark_Matcher_100k(b *testing.B) {
	// init a domain list with 100 TLDs and 1000 sub domains for each TLD
	const (
		tldN = 100
		l2N  = 1000
	)

	rules := make([]string, 0, tldN*l2N)
	names := make([]dnsmsg.Name, 0, tldN*l2N)
	for i := 0; i < tldN; i++ {
		for j := 0; j < l2N; j++ {
			var name dnsmsg.Name
			s := fmt.Sprintf("%d.%d.", j, i)
			err := name.Parse(s)
			if err != nil {
				b.Fatal(err)
			}
			rules = append(rules, s)
			names = append(names, name)
		}
	}

	b.Run("init", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			l := NewLoader()
			for _, s := range rules {
				err := l.Add(utils.Str2BytesUnsafe(s))
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
	for _, s := range rules {
		err := l.Add(utils.Str2BytesUnsafe(s))
		if err != nil {
			b.Fatal(err)
		}
	}
	m, err := l.Compile()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("match", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			name := names[i%len(names)]
			ok := m.Match(name)
			if !ok {
				b.Fatal("unexpected matcher result")
			}
		}
	})
}

func Benchmark_1000k(b *testing.B) {
	r := require.New(b)

	// Init a list with 100 TLDa and 10000 lvl 2 domains for each TLD.
	// Total 100k.
	list := new(bytes.Buffer)
	for tld := 0; tld < 100; tld++ {
		for sub := 0; sub < 10000; sub++ {
			fmt.Fprintf(list, "%d.%d\n", rand.Int64(), tld)
		}
	}

	b.Run("load", func(b *testing.B) {
		r := require.New(b)
		for i := 0; i < b.N; i++ {
			loader := NewLoader()
			err := loader.LoadRulesFromReader(bytes.NewReader(list.Bytes()))
			r.NoError(err)
		}
	})

	loader := NewLoader()
	err := loader.LoadRulesFromReader(bytes.NewReader(list.Bytes()))
	r.NoError(err)
	runtime.GC()
	b.Run("compile", func(b *testing.B) {
		r := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := loader.Compile()
			r.NoError(err)
		}
	})

	matcher, err := loader.Compile()
	r.NoError(err)
	runtime.GC()

	b.Run("match", func(b *testing.B) {
		var name dnsmsg.Name
		err := name.Parse("000000.10000000.1")
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			matcher.Match(name)
		}
	})

	seq := new(bytes.Buffer)
	err = matcher.Serialize(seq)
	r.NoError(err)
	runtime.GC()

	b.Run("serialize", func(b *testing.B) {
		r := require.New(b)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			seq := new(bytes.Buffer)
			err = matcher.Serialize(seq)
			r.NoError(err)
		}
	})

	b.Run("deserialize", func(b *testing.B) {
		r := require.New(b)
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := Deserialize(bytes.NewReader(seq.Bytes()))
			r.NoError(err)
		}
	})
}
