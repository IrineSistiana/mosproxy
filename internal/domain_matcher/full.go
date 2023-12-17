package domainmatcher

import (
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type FullMatcher struct {
	m map[string]struct{}
}

func NewFullMatcher() *FullMatcher {
	return &FullMatcher{m: make(map[string]struct{})}
}

func (m *FullMatcher) MatchString(n string) bool {
	b := normDomainStr(n)
	defer pool.ReleaseBuf(b)
	return m.marchNormed(b.B())
}

func (m *FullMatcher) Match(n []byte) bool {
	b := normDomain(n)
	defer pool.ReleaseBuf(b)
	return m.marchNormed(b.B())
}

func (m *FullMatcher) marchNormed(n []byte) bool {
	_, ok := m.m[string(n)]
	return ok
}

func (m *FullMatcher) Len() int {
	return len(m.m)
}

func (m *FullMatcher) Add(n []byte) {
	b := normDomain(n)
	defer pool.ReleaseBuf(b)
	m.addNormed(b.B())
}

func (m *FullMatcher) addNormed(n []byte) {
	m.m[string(n)] = struct{}{}
}
