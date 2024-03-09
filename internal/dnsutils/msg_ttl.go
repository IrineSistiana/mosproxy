package dnsutils

import (
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// GetMinimalTTL returns the minimal ttl of this msg.
func GetMinimalTTL(m *dnsmsg.Msg) (_ uint32, ok bool) {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, rs := range [...][]dnsmsg.Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, rr := range rs {
			hdr := rr.Hdr()
			if hdr.Type == dnsmsg.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			hasRecord = true
			if ttl := hdr.TTL; ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if !hasRecord { // no ttl applied
		return 0, false
	}
	return minTTL, true
}

// SubtractTTL subtract delta from every m's RR.
// If RR's TTL is smaller than delta, the ttl will be set to 1.
func SubtractTTL(m *dnsmsg.Msg, delta uint32) {
	for _, rs := range [...][]dnsmsg.Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, rr := range rs {
			hdr := rr.Hdr()
			if hdr.Type == dnsmsg.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			if hdr.TTL > delta {
				hdr.TTL -= delta
			} else {
				hdr.TTL = 1
			}
		}
	}
}
