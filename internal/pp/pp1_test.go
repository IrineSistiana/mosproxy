package pp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ParseV1(t *testing.T) {
	r := require.New(t)
	h, err := ParseV1([]byte("PROXY TCP4 255.255.255.255 1.1.1.1 65535 11111\r\n"))
	r.NoError(err)
	r.Equal(uint8(4), h.TcpVersion)
	r.Equal(h.SourceAddr.String(), "255.255.255.255:65535")
	r.Equal(h.DestinationAddr.String(), "1.1.1.1:11111")
}
