package utils

import "github.com/dgraph-io/ristretto/z"

func FastRand() uint32 {
	return z.FastRand()
}
