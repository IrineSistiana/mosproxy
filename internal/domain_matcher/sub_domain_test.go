package domainmatcher

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SubdomainMatcher(t *testing.T) {
	r := require.New(t)

	m := NewDomainMatcher()
	addStr := func(s string) {
		m.Add([]byte(s))
	}

	addStr("com")
	addStr("abc.def")
	r.Equal(m.Len(), 2)

	r.True(m.MatchString("com."))
	r.False(m.MatchString("def."))
	r.True(m.MatchString("a.b.c.com."))
	r.False(m.MatchString("com.a."))

	r.True(m.MatchString("abc.def."))
	r.True(m.MatchString("123.abc.def."))

	r.False(m.MatchString("123.def."))

	addStr(".")
	r.Equal(m.Len(), 1)
	r.True(m.MatchString("1234556."))
}
