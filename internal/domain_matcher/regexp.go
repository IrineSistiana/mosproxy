package domainmatcher

import (
	"regexp"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

// Note: regexp matcher will match a NON-FQDN.
type RegexpMatcher struct {
	m map[string]*regexp.Regexp
}

func NewRegexpMatcher() *RegexpMatcher {
	return &RegexpMatcher{m: make(map[string]*regexp.Regexp)}
}

func (m *RegexpMatcher) Match(n []byte) bool {
	if len(m.m) == 0 {
		return false
	}

	b, err := dnsmsg.ToReadable(n)
	if err != nil {
		return false
	}
	defer pool.ReleaseBuf(b)
	return m.matchReadable(b)
}

func (m *RegexpMatcher) matchReadable(n []byte) bool {
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
