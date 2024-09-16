package domainmatcher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
)

type Loader struct {
	tree *tree
	re   []*regexp.Regexp
	dup  map[string]struct{}
}

func NewLoader() *Loader {
	return &Loader{
		tree: newTree(),
		re:   make([]*regexp.Regexp, 0),
		dup:  make(map[string]struct{}),
	}
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
		n := dnsmsg.NewName()
		defer dnsmsg.ReleaseName(n)
		err := n.Parse(utils.Bytes2StrUnsafe(exp))
		if err != nil {
			return err
		}
		n.ToLower()

		if string(typ) == "full" {
			err = l.tree.Add(n, 0, false)
		} else {
			err = l.tree.Add(n, 0, true)
		}
		return err
	case "regexp":
		_, dup := l.dup[string(exp)]
		if dup {
			return nil
		}
		expr := string(exp)
		r, err := regexp.Compile(expr)
		if err != nil {
			return err
		}
		l.dup[expr] = struct{}{}
		l.re = append(l.re, r)
		return nil
	default:
		return fmt.Errorf("invalid rule type [%s]", typ)
	}
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
	m.ct = ct
	m.re = append(m.re, l.re...)
	return m, nil
}

type Matcher struct {
	ct *compiledTree
	re []*regexp.Regexp
}

func (m *Matcher) Len() int {
	l := 0
	l += m.ct.Len()
	l += len(m.re)
	return l
}

func (m *Matcher) Match(name *dnsmsg.Name) bool {
	if m.ct != nil {
		if _, lvl := m.ct.Match(name); lvl > -2 {
			return true
		}
	}

	if len(m.re) > 0 {
		buf := pool.GetBuf(1024)
		defer pool.ReleaseBuf(buf)

		b := name.AppendReadableTo(buf[:0])
		for _, exp := range m.re {
			if exp.Match(b) {
				return true
			}
		}
	}
	return false
}
