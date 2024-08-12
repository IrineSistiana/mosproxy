package domainmatcher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/domain_matcher/compile"
	"github.com/IrineSistiana/mosproxy/internal/pool"
)

type Loader struct {
	tree *compile.Tree
	re   map[string]*regexp.Regexp
	ct   []*compile.CompiledTree
}

type Matcher struct {
	ct     []*compile.CompiledTree
	regexp []*regexp.Regexp
}

func NewLoader() *Loader {
	return &Loader{
		tree: compile.NewTree(),
		re:   make(map[string]*regexp.Regexp),
	}
}

// n is the domain name in wire format
func (m *Matcher) Match(n []byte) bool {
	if len(m.ct) > 0 {
		labels := make([][]byte, 0, 16)
		scanner := dnsmsg.NewNameScanner(n)
		for scanner.Scan() {
			labels = append(labels, scanner.Label())
		}
		if scanner.Err() != nil {
			return false
		}
		for _, ct := range m.ct {
			if _, lvl := ct.MatchReverse(labels); lvl > -2 {
				return true
			}
		}
	}

	if len(m.regexp) > 0 {
		b, err := dnsmsg.ToReadable(n)
		if err != nil {
			return false
		}
		defer pool.ReleaseBuf(b)
		for _, exp := range m.regexp {
			if exp.Match(b) {
				return true
			}
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
func (l *Loader) Add(rule []byte) error {
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
	case "", "domain", "full":
		builder := dnsmsg.NewNameBuilder()
		defer dnsmsg.ReleaseNameBuilder(builder)
		err := builder.ParseReadable(exp)
		if err != nil {
			return err
		}
		dnsmsg.ToLowerName(builder.Data())
		scanner := dnsmsg.NewNameScanner(builder.Data())
		labels := make([][]byte, 0, 16)
		for scanner.Scan() {
			labels = append(labels, scanner.Label())
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		slices.Reverse(labels)
		if string(typ) == "full" {
			err = l.tree.Add(labels, 0, false)
		} else {
			err = l.tree.Add(labels, 0, true)
		}
		return err
	case "regexp":
		_, dup := l.re[string(exp)]
		if dup {
			return nil
		}
		s := string(exp)
		r, err := regexp.Compile(s)
		if err != nil {
			return err
		}
		l.re[s] = r
		return nil
	default:
		return fmt.Errorf("invalid rule type [%s]", typ)
	}
}

func (l *Loader) LoadCompiledTree(r io.Reader) error {
	ct, err := compile.Deserialize(r)
	if err != nil {
		return err
	}
	l.ct = append(l.ct, ct)
	return nil
}

func (l *Loader) LoadRulesFromReader(r io.Reader) error {
	s := bufio.NewScanner(r)
	line := 0
	for s.Scan() {
		line++
		b := s.Bytes()
		if i := bytes.IndexByte(b, '#'); i >= 0 {
			b = b[:i]
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			continue
		}
		err := l.Add(b)
		if err != nil {
			return fmt.Errorf("invalid rule at #%d, %w", line, err)
		}
	}
	return s.Err()
}

func (l *Loader) Compile() (*Matcher, error) {
	m := new(Matcher)
	ct, err := l.tree.Compile()
	if err != nil {
		return nil, err
	}
	if ct.Len() > 0 {
		l.ct = append(l.ct, ct)
	}
	m.ct = l.ct

	for _, exp := range l.re {
		m.regexp = append(m.regexp, exp)
	}
	return m, nil
}

func (m *Matcher) Len() int {
	l := 0
	for _, ct := range m.ct {
		l += ct.Len()
	}
	l += len(m.regexp)
	return l
}
