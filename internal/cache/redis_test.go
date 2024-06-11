package cache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_RedisCache(t *testing.T) {
	u := os.Getenv("MOSPROXY_TEST_REDIS_SERVER_URL")
	if len(u) == 0 {
		t.Skip("MOSPROXY_TEST_REDIS_SERVER_URL not set, skipping redis tests")
	}

	r := require.New(t)
	c, err := NewRedisCache(u, nil)
	r.NoError(err)
	_, err = c.Ping(context.Background()) // bring backend online now
	r.NoError(err)

	k := []byte("key")
	v := []byte("value")

	st := time.Now()
	et := st.Add(time.Minute)
	c.Store(k, st, et, v, false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gotSt, gotEt, gotV := c.Get(ctx, k)
	r.Equal(v, gotV)
	r.Equal(st.Unix(), gotSt.Unix())
	r.Equal(et.Unix(), gotEt.Unix())
}
