package domainmatcher

import (
	"bytes"
	"fmt"
)

type MixMatcher struct {
	full   *FullMatcher
	domain *DomainMatcher
	regexp *RegexpMatcher
}

func NewMixMatcher() *MixMatcher {
	return &MixMatcher{
		full:   NewFullMatcher(),
		domain: NewDomainMatcher(),
		regexp: NewRegexpMatcher(),
	}
}

func (m *MixMatcher) Match(n []byte) bool {
	for _, subMatcher := range [...]interface{ Match([]byte) bool }{m.full, m.domain, m.regexp} {
		if subMatcher == nil {
			continue
		}
		ok := subMatcher.Match(n)
		if ok {
			return true
		}
	}
	return false
}

func (m *MixMatcher) MatchString(n string) bool {
	for _, subMatcher := range [...]interface{ MatchString(string) bool }{m.full, m.domain, m.regexp} {
		ok := subMatcher.MatchString(n)
		if ok {
			return true
		}
	}
	return false
}

func (m *MixMatcher) Add(s []byte) error {
	var (
		typ  []byte
		rule []byte
	)
	if i := bytes.IndexByte(s, ':'); i >= 0 {
		typ = s[:i]
		rule = s[i+1:]
	} else {
		rule = s
	}

	switch string(typ) {
	case "", "domain":
		m.domain.Add(rule)
		return nil
	case "full":
		m.full.Add(rule)
		return nil
	case "regexp":
		return m.regexp.Add(string(rule))
	default:
		return fmt.Errorf("invalid rule type [%s]", typ)
	}
}

func (m *MixMatcher) Len() int {
	l := 0
	l += m.full.Len()
	l += m.domain.Len()
	l += m.regexp.Len()
	return l
}
