package pool

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_pool(t *testing.T) {
	r := require.New(t)

	tts := []struct {
		size int
		cap  int
	}{
		{0, 0},
		{64, 64},
		{65, 128},
		{256, 256},
		{257, 320},
	}

	for _, tt := range tts {
		b := GetBuf(tt.size)
		r.Equalf(tt.size, b.Len(), "invalid size, tt: %v", tt)
		r.Equalf(tt.cap, b.Cap(), "invalid cap, tt: %v", tt)
		ReleaseBuf(b)
	}
}

func Test_sp(t *testing.T) {
	r := require.New(t)

	// spIdx
	r.Equal(0, spIdx(1))
	r.Equal(1, spIdx(2))
	r.Equal(2, spIdx(3))
	r.Equal(2, spIdx(4))
	r.Equal(3, spIdx(5))
	r.Equal(3, spIdx(8))
	r.Equal(4, spIdx(9))
	r.Equal(8, spIdx(256))

	// spSize
	r.Equal(1, spSize(0))
	r.Equal(2, spSize(1))
	r.Equal(4, spSize(2))
	r.Equal(8, spSize(3))
	r.Equal(256, spSize(8))
}

func Test_lp(t *testing.T) {
	r := require.New(t)

	// spIdx
	tts := []struct {
		size int
		h, l int
	}{
		// 256-320-384-448-512
		{257, 0, 0},
		{320, 0, 0},
		{321, 0, 1},
		{384, 0, 1},
		{385, 0, 2},
		{448, 0, 2},
		{449, 0, 3},
		{512, 0, 3},

		// 512-640-768-896-1024
		{513, 1, 0},
		{640, 1, 0},
		{768, 1, 1},
		{896, 1, 2},
		{1024, 1, 3},
		{1 << 30, 21, 3},
		{(1 << 30) + 1, 22, 0},
	}
	for _, tt := range tts {
		h, l := lpIdx(tt.size)
		r.Equalf(tt.h, h, "h idx invalid: tt: %v", tt)
		r.Equalf(tt.l, l, "l idx invalid:tt: %v", tt)
	}

	tts = []struct {
		size int
		h, l int
	}{
		{320, 0, 0},
		{384, 0, 1},
		{768, 1, 1},
		{1024, 1, 3},
		{1280, 2, 0},
	}
	for _, tt := range tts {
		size := lpSize(tt.h, tt.l)
		r.Equalf(tt.size, size, "tt: %v", tt)
	}
}
