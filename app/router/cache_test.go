package router

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/klauspost/compress/s2"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func Benchmark_Compress(b *testing.B) {
	randIp6 := func() net.IP {
		ip := make([]byte, 16)
		rand.Reader.Read(ip)
		return ip
	}

	r := require.New(b)
	name := "test.test.test."
	rrs := []dns.RR{
		&dns.A{A: net.IPv4bcast},
		&dns.AAAA{AAAA: net.IPv6loopback},
		&dns.SOA{Ns: name, Mbox: name},
		&dns.PTR{Ptr: name},
		&dns.CNAME{Target: name},
		&dns.MX{Mx: name},
	}
	for i := 0; i < 5; i++ {
		rrs = append(rrs, &dns.AAAA{AAAA: randIp6()})
	}
	for _, v := range rrs {
		v.Header().Name = name
	}

	m := new(dns.Msg)
	m.Answer = rrs
	m.Compress = true

	msgBin, err := m.Pack()
	r.NoError(err)
	b.Run("s2 decompress", func(b *testing.B) {
		dst := make([]byte, s2.MaxEncodedLen(len(msgBin)))
		for i := 0; i < b.N; i++ {
			out := s2.Encode(dst, msgBin)
			_ = out
		}
	})
}
