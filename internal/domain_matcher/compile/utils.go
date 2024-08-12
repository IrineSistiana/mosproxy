package compile

import "math"

func append32bs[T []byte | string](s []byte, d T) (segAddr, []byte, bool) {
	if t := len(s) + len(d); t > math.MaxInt32 || t < 0 {
		return segAddr{}, s, false
	}
	sa := segAddr{
		off: int32(len(s)),
		l:   int32(len(d)),
	}
	s = append(s, d...)
	return sa, s, true
}

func validSegAddr(sa segAddr, targetLen int32) bool {
	end := sa.off + sa.l
	invalid := sa.off < 0 || sa.off > targetLen || sa.l < 0 ||
		end < 0 || end > targetLen
	return !invalid
}
