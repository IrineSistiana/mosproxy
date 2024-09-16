package router

import (
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func Test_findECS(t *testing.T) {
	r := require.New(t)
	makeReq := func(addr netip.Prefix) *dnsmsg.Msg {
		family := 1
		if addr.Addr().Is6() {
			family = 2
		}

		m := new(dns.Msg)
		m.SetEdns0(512, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
			Padding: make([]byte, 512),
		})
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Family:        uint16(family),
			SourceNetmask: uint8(addr.Bits()),
			Address:       addr.Addr().AsSlice(),
		})
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
			Padding: make([]byte, 512),
		})

		b, err := m.Pack()
		r.NoError(err)

		m2, err := dnsmsg.UnpackMsg(b)
		r.NoError(err)
		return m2
	}

	tests := []struct {
		name string
		addr string
	}{
		{"v4", "0.0.0.0/0"},
		{"v4", "127.0.0.0/24"},
		{"v4", "127.0.0.1/32"},
		{"v6", "::0/0"},
		{"v6", "::0/24"},
		{"v6", "::1/128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := netip.ParsePrefix(tt.addr)
			r.NoError(err)

			m := makeReq(p)
			if got := findECS(m); got != p {
				t.Errorf("findECS() = %v, want %v", got, p)
			}
		})
	}
}

func Test_packECS(t *testing.T) {
	r := require.New(t)
	testFn := func(s string) {
		p, err := netip.ParsePrefix(s)
		r.NoError(err)
		p = p.Masked()

		m := dnsmsg.NewMsg()
		opt := newEDNS0(0)
		opt.Data = makeEdns0ClientSubnetReqOpt(p)
		m.Additionals = append(m.Additionals, opt)

		bb, err := m.Pack(nil, false, 0)
		r.NoError(err)

		m2 := new(dns.Msg)
		err = m2.Unpack(bb)
		r.NoError(err)

		opt2 := m2.IsEdns0()
		r.NotNil(opt2)
		r.Equal(1, len(opt2.Option))

		ecs, ok := opt2.Option[0].(*dns.EDNS0_SUBNET)
		r.True(ok)

		gotAddr, ok := netip.AddrFromSlice(ecs.Address)
		r.True(ok)
		gotAddr = gotAddr.Unmap()

		gotMask := ecs.SourceNetmask
		gotP := netip.PrefixFrom(gotAddr, int(gotMask))

		r.Equal(p, gotP)
	}
	testFn("1.2.3.4/0")
	testFn("1.2.3.4/1")
	testFn("1.2.3.4/16")
	testFn("1.2.3.4/32")
	testFn("1::2/0")
	testFn("1::2/64")
	testFn("1::2/127")
	testFn("1::2/128")
}
