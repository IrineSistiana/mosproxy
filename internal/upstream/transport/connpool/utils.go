package connpool

import "math/bits"

func canTakeReq(status ConnStatus) bool {
	return !status.Closed && status.AvailableReq > 0
}

func assignWorkload(to *uint64, l uint64, limit uint64) bool {
	sum, co := bits.Add64(*to, l, 0)
	if co > 0 || sum > limit {
		return false
	}
	*to = sum
	return true
}
