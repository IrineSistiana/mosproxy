package dnsmsg

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	r := require.New(t)

	testFn := func(s string, expect error) {
		n := NewName()
		err := n.Parse(s)
		if err != nil {
			r.ErrorIs(err, expect)
			return
		}

		out, _, err := dns.UnpackDomainName(n.Data(), 0)
		r.NoError(err)
		r.Equal(dns.Fqdn(s), dns.Fqdn(out))
	}

	// root
	testFn("", nil)
	testFn(".", nil)

	for i := 0; i < 100; i++ {
		s := fmt.Sprintf("%x.%x.%x", rand.Int31(), rand.Int31(), rand.Int31())
		testFn(s, nil)
	}

	testFn(".a", errZeroSegLen)
	testFn("a.b.c..d", errZeroSegLen)
	testFn("a.b."+strings.Repeat("c", 63)+".d", nil)
	testFn("a.b."+strings.Repeat("c", 64)+".d", errSegTooLong)
	testFn(strings.Repeat("c.", 127), nil)
	testFn(strings.Repeat("c.", 128), errNameTooLong)
}

func TestName_AppendReadableTo(t *testing.T) {
	r := require.New(t)
	testFn := func(s, w string) {
		n := NewName()
		err := n.Parse(s)
		r.NoError(err)

		got := n.AppendReadableTo(nil)
		r.Equal(w, string(got))
	}

	testFn("1.2.3", "1.2.3")
	testFn("1.2.3.", "1.2.3")
	testFn("a.bb.ccc.dddd", "a.bb.ccc.dddd")
	testFn("", ".")
}
