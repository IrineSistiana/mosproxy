package domainmatcher

import (
	"testing"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/stretchr/testify/require"
)

func TestMixMatcher_Match(t *testing.T) {
	r := require.New(t)

	m := NewMixMatcher()

	add := func(rule string) {
		err := m.Add([]byte(rule))
		r.NoError(err)
	}
	match := func(n string, expect bool) {
		var builder dnsmsg.NameBuilder
		err := builder.ParseReadable([]byte(n))
		r.NoError(err)
		res := m.Match(builder.Data())
		r.Equalf(expect, res, "match [%s]", n)
	}

	add("full:full.FULL.full")

	add("regexp:^full.reg.exp$")
	add("regexp:^reg.exp.prefix")

	add("domain:domain.SUFFIX")
	add("CAP.SUFFIX")

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
