package rvlookup

import (
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/stretchr/testify/require"
)

func Test_parsePtr(t *testing.T) {
	r := require.New(t)
	testFn := func(n string, want string) {
		var name dnsmsg.Name
		err := name.Parse(n)
		r.NoError(err)
		wantAddr, err := netip.ParseAddr(want)
		r.NoError(err)

		addr, err := parsePtr(name)
		r.NoError(err)
		r.Truef(addr == wantAddr, "got=%s, want=%s", addr, want)
	}

	testFn("0.0.0.0.in-addr.arpa", "0.0.0.0")
	testFn("4.4.8.8.in-addr.arpa", "8.8.4.4")
	testFn("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::567:89ab")

	testErrFn := func(n string) {
		var name dnsmsg.Name
		err := name.Parse(n)
		r.NoError(err)
		addr, err := parsePtr(name)
		r.Error(err)
		r.False(addr.IsValid())
	}

	testErrFn("x.x.x")
	testErrFn("0.0.0.0.in-addr.arpa.xxx")                                                     // invalid domain
	testErrFn("0.0.0.0.in-addrxxx.arpa")                                                      // invalid domain
	testErrFn("0.0.0.in-addr.arpa")                                                           // 3 labels
	testErrFn("0.0.0.0.0.in-addr.arpa")                                                       // 5 labels
	testErrFn("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6_xxx.arpa") // invalid domain
	testErrFn("9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")         // 30 labels
	testErrFn("0.0.b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa") // 34 labels
}
