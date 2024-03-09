package domainmatcher

type FullMatcher struct {
	m map[string]struct{}
}

func NewFullMatcher() *FullMatcher {
	return &FullMatcher{m: make(map[string]struct{})}
}

func (m *FullMatcher) Match(n []byte) bool {
	_, ok := m.m[string(n)]
	return ok
}

func (m *FullMatcher) Len() int {
	return len(m.m)
}

func (m *FullMatcher) Add(n []byte) {
	m.m[string(n)] = struct{}{}
}
