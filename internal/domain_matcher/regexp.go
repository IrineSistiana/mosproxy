package domainmatcher

import (
	"regexp"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

// Note: regexp matcher will match against a NON-FQDN.
type RegexpMatcher struct {
	m map[string]*regexp.Regexp
}

func NewRegexpMatcher() *RegexpMatcher {
	return &RegexpMatcher{m: make(map[string]*regexp.Regexp)}
}

func (m *RegexpMatcher) MatchString(n string) bool {
	b := normDomainStr(n)
	defer pool.ReleaseBuf(b)
	return m.matchNormed(b.B())
}

func (m *RegexpMatcher) Match(n []byte) bool {
	b := normDomain(n)
	defer pool.ReleaseBuf(b)
	return m.matchNormed(b.B())
}

func (m *RegexpMatcher) matchNormed(n []byte) bool {
	for _, r := range m.m {
		if r.Match(n) {
			return true
		}
	}
	return false
}

func (m *RegexpMatcher) Len() int {
	return len(m.m)
}

func (m *RegexpMatcher) Add(exp string) error {
	_, dup := m.m[exp]
	if dup {
		return nil
	}
	r, err := regexp.Compile(exp)
	if err != nil {
		return err
	}
	m.m[exp] = r
	return nil
}
