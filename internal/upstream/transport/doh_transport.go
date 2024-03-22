package transport

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/rs/zerolog"
)

const (
	dohMaximumMsgSize = 65535
	defaultDoHTimeout = time.Second * 6
)

var _ Transport = (*DoHTransport)(nil)

// DoHTransport is a DNS-over-HTTPS (RFC 8484) upstream using GET method.
type DoHTransport struct {
	rt     http.RoundTripper
	logger *zerolog.Logger
	closer io.Closer

	urlTemplate *urlpkg.URL
	reqTemplate *http.Request
}

type DoHTransportOpts struct {
	EndPointUrl  string
	RoundTripper http.RoundTripper
	Closer       io.Closer
	Logger       *zerolog.Logger
}

func NewDoHTransport(opts DoHTransportOpts) (*DoHTransport, error) {
	req, err := http.NewRequest(http.MethodGet, opts.EndPointUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse http request, %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}
	req.Header["User-Agent"] = nil // Don't let go http send a default user agent header.

	t := &DoHTransport{
		rt:          opts.RoundTripper,
		closer:      opts.Closer,
		logger:      nonNilLogger(opts.Logger),
		urlTemplate: req.URL,
		reqTemplate: req,
	}
	return t, nil
}

func (u *DoHTransport) Close() error {
	if u.closer != nil {
		return u.Close()
	}
	return nil
}

var (
	bufPool4k = pool.NewBytesBufPool(4096)
)

func (u *DoHTransport) ExchangeContext(ctx context.Context, q []byte) (*dnsmsg.Msg, error) {
	l := len(q)
	if l < dnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}
	if l > dohMaximumMsgSize {
		return nil, ErrPayloadOverFlow
	}
	bp := copyMsg(q)
	bs := bp
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484#section-4.1
	bs[0] = 0
	bs[1] = 0

	rawQuery := make([]byte, 4+base64.RawURLEncoding.EncodedLen(len(bs)))
	copy(rawQuery, "dns=")

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484#section-6.
	base64.RawURLEncoding.Encode(rawQuery[4:], bs)
	pool.ReleaseBuf(bp)

	type res struct {
		r   *dnsmsg.Msg
		err error
	}
	resChan := make(chan res, 1)
	go func() {
		// We overwrite the ctx with a fixed timeout context here.
		// Because the http package may close the underlay connection
		// if the context is done before the query is completed. This
		// reduces the connection reuse efficiency.
		ctx, cancel := context.WithTimeout(context.Background(), defaultDoHTimeout)
		defer cancel()
		r, err := u.exchange(ctx, bytesToStringUnsafe(rawQuery))
		if err != nil {
			u.logger.Warn().Err(err).Msg("query failed")
		}
		resChan <- res{r: r, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case res := <-resChan:
		r := res.r
		err := res.err
		if r != nil {
			r.Header.ID = binary.BigEndian.Uint16(q)
		}
		return r, err
	}
}

func (u *DoHTransport) exchange(ctx context.Context, rawQuery string) (*dnsmsg.Msg, error) {
	req := u.reqTemplate.WithContext(ctx)
	req.URL = new(urlpkg.URL)
	*req.URL = *u.urlTemplate
	req.URL.RawQuery = rawQuery
	resp, err := u.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		body1k, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if body1k != nil {
			return nil, fmt.Errorf("bad http status codes %d with body [%s]", resp.StatusCode, body1k)
		}
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	bb := bufPool4k.Get()
	defer bufPool4k.Release(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}
	return dnsmsg.UnpackMsg(bb.Bytes())
}
