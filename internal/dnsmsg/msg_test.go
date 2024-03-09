package dnsmsg

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func runPackUnpackTest(t *testing.T, m *dns.Msg) {
	r := require.New(t)

	wire, err := m.Pack()
	r.NoError(err)

	m2 := NewMsg()
	err = m2.Unpack(wire)
	r.NoError(err)

	for _, compression := range []bool{false, true} {
		buf := make([]byte, m2.Len())
		n, err := m2.Pack(buf, compression, 0)
		r.NoError(err)

		wireGot := buf[:n]
		msgGot := new(dns.Msg)
		err = msgGot.Unpack(wireGot)
		r.NoError(err)
		r.Equal(m.String(), msgGot.String())
	}
}

func Test_Question(t *testing.T) {
	m := new(dns.Msg)
	for i := 0; i < 5; i++ {
		m.Question = append(
			m.Question,
			dns.Question{
				Name:   fmt.Sprintf("%d.test.test.", i),
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET},
		)
	}
	runPackUnpackTest(t, m)
}

func Test_Resources(t *testing.T) {
	name := "test.test."
	rrs := []dns.RR{
		&dns.A{A: net.IPv4bcast, Hdr: dns.RR_Header{Name: "a.name.", Rrtype: dns.TypeA}},
		&dns.AAAA{AAAA: net.IPv6loopback, Hdr: dns.RR_Header{Name: "aaaa.name.", Rrtype: dns.TypeAAAA}},

		&dns.PTR{Ptr: "ptr.data.", Hdr: dns.RR_Header{Name: "ptr.name.", Rrtype: dns.TypePTR}},
		&dns.CNAME{Target: "cname.data.", Hdr: dns.RR_Header{Name: "cname.name.", Rrtype: dns.TypeCNAME}},
		&dns.NS{Ns: "ns.data.", Hdr: dns.RR_Header{Name: "ns.name.", Rrtype: dns.TypeNS}},

		&dns.MX{Mx: "mx.data.", Hdr: dns.RR_Header{Name: "mx.name.", Rrtype: dns.TypeMX}},
		&dns.SOA{Ns: "soa.ns.data.", Mbox: "soa.mbox.data.", Hdr: dns.RR_Header{Name: "soa.name.", Rrtype: dns.TypeSOA}},

		&dns.TXT{Txt: []string{"txt.data"}, Hdr: dns.RR_Header{Name: "txt.name.", Rrtype: dns.TypeTXT}},
	}

	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Answer = append(m.Answer, rrs...)
	runPackUnpackTest(t, m)
}

func Benchmark_Msg(b *testing.B) {
	r := require.New(b)
	name := "test.test.test."
	rrs := []dns.RR{
		&dns.A{A: net.IPv4bcast, Hdr: dns.RR_Header{Rrtype: dns.TypeA}},
		&dns.AAAA{AAAA: net.IPv6loopback, Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}},
		&dns.SOA{Ns: name, Mbox: name, Hdr: dns.RR_Header{Rrtype: dns.TypeSOA}},
		&dns.PTR{Ptr: name, Hdr: dns.RR_Header{Rrtype: dns.TypePTR}},
		&dns.CNAME{Target: name, Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME}},
		&dns.MX{Mx: name, Hdr: dns.RR_Header{Rrtype: dns.TypeMX}},
	}
	for i := 0; i < 10; i++ {
		rrs = append(rrs, &dns.AAAA{AAAA: net.IPv6loopback, Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}})
	}
	for _, v := range rrs {
		v.Header().Name = name
	}

	m := new(dns.Msg)
	m.Answer = rrs
	m.Compress = true
	msgBin, err := m.Pack()
	r.NoError(err)

	b.ReportAllocs()
	b.ResetTimer()

	b.Run("Msg Unpack", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rm := NewMsg()
			err := rm.Unpack(msgBin)
			if err != nil {
				b.Fatal(err)
			}
			ReleaseMsg(rm)
		}
	})
	b.Run("dns.Msg Unpack", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m := new(dns.Msg)
			err := m.Unpack(msgBin)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Msg Pack", func(b *testing.B) {
		rm := NewMsg()
		err := rm.Unpack(msgBin)
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, rm.Len())
		b.Run("with compression", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := rm.Pack(buf, true, 0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("no compression", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := rm.Pack(buf, false, 0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("dns.Msg Pack", func(b *testing.B) {
		m := new(dns.Msg)
		err := m.Unpack(msgBin)
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, 0, 4096)
		b.Run("with compression", func(b *testing.B) {
			m.Compress = true
			for i := 0; i < b.N; i++ {
				_, err := m.PackBuffer(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("no compression", func(b *testing.B) {
			m.Compress = false
			for i := 0; i < b.N; i++ {
				_, err := m.PackBuffer(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
