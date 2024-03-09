package domainmatcher

import (
	"bytes"
	"fmt"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
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

// n is the domain name in wire format
func (m *MixMatcher) Match(n []byte) bool {
	for _, subMatcher := range [...]interface{ Match([]byte) bool }{m.full, m.domain, m.regexp} {
		ok := subMatcher.Match(n)
		if ok {
			return true
		}
	}
	return false
}

// Add adds rule to the matcher.
// Rule format: <typ:><exp>
// <typ> can be  domain | full | regexp
// Default type is domain if <typ> is omitted.
// <exp> is a domain name, escaping is not supported.
// For regexp, <exp> is a regular expression for Non-fqdn, lower-case domains.
//
// E.g. "google.com", "regexp:google.com$"
func (m *MixMatcher) Add(rule []byte) error {
	var (
		typ []byte
		exp []byte
	)
	if i := bytes.IndexByte(rule, ':'); i >= 0 {
		typ = rule[:i]
		exp = rule[i+1:]
	} else {
		exp = rule
	}

	switch string(typ) {
	case "", "domain":
		var builder dnsmsg.NameBuilder
		err := builder.ParseReadable(exp)
		if err != nil {
			return err
		}
		dnsmsg.ToLowerName(builder.Data())
		scanner := dnsmsg.NewNameScanner(builder.Data())
		labels := make([][]byte, 0, 8)
		for scanner.Scan() {
			labels = append(labels, scanner.Label())
		}
		m.domain.Add(labels)
		return nil
	case "full":
		var builder dnsmsg.NameBuilder
		err := builder.ParseReadable(exp)
		if err != nil {
			return err
		}
		dnsmsg.ToLowerName(builder.Data())
		m.full.Add(builder.Data())
		return nil
	case "regexp":
		return m.regexp.Add(string(exp))
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
