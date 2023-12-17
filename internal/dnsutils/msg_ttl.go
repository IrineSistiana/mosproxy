package dnsutils

import (
	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
)

// GetMinimalTTL returns the minimal ttl of this msg.
func GetMinimalTTL(m *dnsmsg.Msg) (_ uint32, ok bool) {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, set := range [...]*dnsmsg.List[*dnsmsg.Resource]{&m.Answers, &m.Authorities, &m.Answers} {
		for n := set.Head(); n != nil; n = n.Next() {
			rr := n.Value()
			if rr.Type == dnsmsg.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			hasRecord = true
			if ttl := rr.TTL; ttl < minTTL {
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
	for _, set := range [...]*dnsmsg.List[*dnsmsg.Resource]{&m.Answers, &m.Authorities, &m.Additionals} {
		for n := set.Head(); n != nil; n = n.Next() {
			rr := n.Value()
			if rr.Type == dnsmsg.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			if rr.TTL > delta {
				rr.TTL = rr.TTL - delta
			} else {
				rr.TTL = 1
			}
		}
	}
}
