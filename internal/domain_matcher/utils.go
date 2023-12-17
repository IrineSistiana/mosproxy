package domainmatcher

import "github.com/IrineSistiana/mosproxy/internal/pool"

func normDomain(s []byte) *pool.Buffer {
	s = trimSuffixDot(s)
	b := pool.GetBuf(len(s))
	copy(b.B(), s)
	asciiToLower(b.B())
	return b
}

func normDomainStr(s string) *pool.Buffer {
	s = trimSuffixDotString(s)
	b := pool.GetBuf(len(s))
	copy(b.B(), s)
	asciiToLower(b.B())
	return b
}

func trimSuffixDot(s []byte) []byte {
	if len(s) == 0 {
		return s
	}
	tail := len(s) - 1
	if s[tail] == '.' {
		return s[:tail]
	}
	return s
}

func trimSuffixDotString(s string) string {
	if len(s) == 0 {
		return s
	}
	tail := len(s) - 1
	if s[tail] == '.' {
		return s[:tail]
	}
	return s
}

func asciiToLower(s []byte) {
	for i, c := range s {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
			s[i] = c
		}
	}
}
