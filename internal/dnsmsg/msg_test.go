package dnsmsg

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func Test_Pack_Unpack(t *testing.T) {
	r := require.New(t)

	name := "test.test."

	makeMsg := func(t *testing.T, q dns.Question, ans []dns.RR) []byte {
		t.Helper()
		r := require.New(t)
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.Answer = append(m.Answer, ans...)
		b, err := m.Pack()
		r.NoError(err)
		return b
	}

	t.Run("unpack question", func(t *testing.T) {
		b := makeMsg(t, dns.Question{Name: name, Qtype: 1, Qclass: 1}, nil)
		// test unpack
		m := NewMsg()
		err := m.Unpack(b)
		r.NoError(err)

		r.Equal(1, m.Questions.Len())
		q := m.Questions.Head()
		r.True(string(q.Name.B()) == name)
		r.True(q.Class == 1)
		r.True(q.Type == 1)
	})

	t.Run("unpack and pack rr", func(t *testing.T) {
		rrs := []dns.RR{
			// data is binary
			&dns.A{A: net.IPv4bcast, Hdr: dns.RR_Header{Rrtype: dns.TypeA}},
			&dns.AAAA{AAAA: net.IPv6loopback, Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}},
			&dns.TXT{Txt: []string{"0000000000000000000000"}, Hdr: dns.RR_Header{Rrtype: dns.TypeTXT}},

			// data is <domain-name>
			&dns.PTR{Ptr: name, Hdr: dns.RR_Header{Rrtype: dns.TypePTR}},
			&dns.CNAME{Target: name, Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME}},
			&dns.NS{Ns: name, Hdr: dns.RR_Header{Rrtype: dns.TypeNS}},

			// data contains <domain-name>
			&dns.MX{Mx: name, Hdr: dns.RR_Header{Rrtype: dns.TypeMX}},
			&dns.SOA{Ns: name, Mbox: name, Hdr: dns.RR_Header{Rrtype: dns.TypeSOA}},
		}
		for _, rr := range rrs {
			rr.Header().Name = name
			rr.Header().Class = dns.ClassINET
		}

		for _, wantRr := range rrs {
			wantRrStr := wantRr.String()

			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeA)
			m.Answer = append(m.Answer, wantRr, wantRr)

			msgBytes, err := m.Pack()
			r.NoError(err)

			// test unpack
			rawMsg := NewMsg()
			err = rawMsg.Unpack(msgBytes)
			r.NoError(err)

			gotRR := 0
			for iter := rawMsg.Answers.Iter(); iter.Next(); {
				rr := iter.Value()
				gotRR++
				r.True(string(rr.Name.B()) == name)
			}
			r.Equal(2, gotRR)

			// test pack
			for _, compression := range [...]bool{true, false} {
				noCompressionLen := rawMsg.Len()
				repackedMsgBytes := make([]byte, noCompressionLen)
				n, err := rawMsg.Pack(repackedMsgBytes, compression, 0)
				r.NoError(err)
				if compression == false {
					r.True(n == noCompressionLen)
				}
				repackedMsgBytes = repackedMsgBytes[:n]

				m = new(dns.Msg)
				err = m.Unpack(repackedMsgBytes)
				r.NoError(err)

				r.Len(m.Answer, 2)
				for _, gotRr := range m.Answer {
					gotRrStr := gotRr.String()
					r.True(gotRrStr == wantRrStr)
				}
			}
		}
	})

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

	b.Run("Msg copy", func(b *testing.B) {
		rm := NewMsg()
		err := rm.Unpack(msgBin)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			newMsg := rm.Copy()
			ReleaseMsg(newMsg)
		}
	})
}
