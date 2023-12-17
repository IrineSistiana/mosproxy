package utils

import "testing"

func Benchmark_FastRand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		FastRand()
	}
}
