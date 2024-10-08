package rvlookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"github.com/IrineSistiana/mosproxy/app/router"
	"github.com/IrineSistiana/mosproxy/internal/utils"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/maypok86/otter"
	"github.com/prometheus/client_golang/prometheus"
)

type Args struct {
	CacheSize int `yaml:"cache_size"`
	CacheTtl  int `yaml:"cache_ttl"`
}

const (
	mwName = "rvlookup"
)

func init() {
	router.RegMiddleware(mwName, NewRvLookup)
}

type RvLookup struct {
	ctx  router.PluginCtx
	next router.Middleware
	args Args

	cache     otter.Cache[netip.Addr, string]
	cacheSize prometheus.GaugeFunc
	strCache  otter.Cache[string, string] // cache for same domain strings to save memory
}

func NewRvLookup(ctx router.PluginCtx, args map[string]any, next router.Middleware) (router.Middleware, error) {
	a := Args{}
	err := router.WakeDecode(&a, args, "yaml")
	if err != nil {
		return nil, fmt.Errorf("invalid args, %w", err)
	}

	h := &RvLookup{
		ctx:  ctx,
		next: next,
		args: a,
	}

	b, err := otter.NewBuilder[netip.Addr, string](a.CacheSize)
	if err != nil {
		return nil, err
	}
	c, err := b.WithTTL(time.Duration(a.CacheTtl) * time.Second).
		Cost(func(key netip.Addr, value string) uint32 {
			return uint32(unsafe.Sizeof(key)) + uint32(unsafe.Sizeof(value)) + uint32(len(value))
		}).
		Build()
	if err != nil {
		return nil, err
	}
	h.cache = c

	sb, err := otter.NewBuilder[string, string](a.CacheSize)
	if err != nil {
		return nil, err
	}
	sc, err := sb.WithTTL(time.Duration(a.CacheTtl) * time.Second).
		Cost(func(key, value string) uint32 { return uint32(unsafe.Sizeof(value)) + uint32(len(value)) }).
		Build()
	if err != nil {
		return nil, err
	}
	h.strCache = sc

	h.cacheSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cache_size",
		Help: "The number of ptr (ip name pair) that is cached",
	}, func() float64 { return float64(c.Size()) })
	return h, nil
}

func (h *RvLookup) Handle(ctx context.Context, q *router.QueryCtx) {
	qq := q.Question
	if qq.Type == dnsmsg.TypePTR && qq.Class == dnsmsg.ClassINET {
		rr := h.lookup(qq.Name)
		if rr != nil {
			resp := dnsmsg.NewMsg()
			resp.Questions = append(resp.Questions, q.Question.Copy())
			resp.Answers = append(resp.Answers, rr)
			q.SetRespFrom(resp, mwName)
			return
		}
	}
	h.next.Handle(ctx, q)

	if resp := q.Resp(); resp != nil && qq.Class == dnsmsg.ClassINET && (qq.Type == dnsmsg.TypeA || qq.Type == dnsmsg.TypeAAAA) {
		for _, rr := range resp.Answers {
			switch rr := rr.(type) {
			case *dnsmsg.A:
				h.saveNameAddr(rr.Name, netip.AddrFrom4(rr.A))
			case *dnsmsg.AAAA:
				h.saveNameAddr(rr.Name, netip.AddrFrom16(rr.AAAA).Unmap())
			}
		}
	}
}

func (h *RvLookup) lookup(n dnsmsg.Name) *dnsmsg.NAMEResource {
	addr, err := parsePtr(n)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()

	raw, ok := h.cache.Get(addr)
	if ok {
		ptr := dnsmsg.NewNAME()
		ptr.Name.CopyFrom(n)
		ptr.Class = dnsmsg.ClassINET
		ptr.Type = dnsmsg.TypePTR
		ptr.TTL = 10
		err := dnsmsg.ParseNameRaw(&ptr.NameData, raw)
		if err != nil {
			h.ctx.Logger.Err(err).Msg("internel err: invalid raw name")
			return nil
		}
		return ptr
	}
	return nil
}

var (
	errInvalidPtrZone  = errors.New("invalid ptr zone")
	errInvalidLabelLen = errors.New("invalid label len")
)

func parsePtr(n dnsmsg.Name) (netip.Addr, error) {
	labels := n.Labels()
	if len(labels) < 2 {
		return netip.Addr{}, errInvalidLabelLen
	}

	if string(labels[len(labels)-1]) != "arpa" {
		return netip.Addr{}, errInvalidPtrZone
	}

	switch string(labels[len(labels)-2]) {
	case "in-addr":
		return parseIpv4(labels[:len(labels)-2])
	case "ip6":
		return parseIpv16(labels[:len(labels)-2])
	default:
		return netip.Addr{}, errInvalidPtrZone
	}
}

func parseIpv4(labels [][]byte) (netip.Addr, error) {
	if len(labels) != 4 {
		return netip.Addr{}, errInvalidLabelLen
	}
	var buf [4]byte
	for i := 0; i < 4; i++ {
		label := labels[3-i]
		u, err := strconv.ParseUint(utils.Bytes2StrUnsafe(label), 10, 8)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid label %s: %s", label, err)
		}
		buf[i] = byte(u)
	}
	return netip.AddrFrom4(buf), nil
}

func parseIpv16(labels [][]byte) (netip.Addr, error) {
	if len(labels) != 32 {
		return netip.Addr{}, errInvalidLabelLen
	}
	var buf [16]byte
	for i := 0; i < 32; i++ {
		label := labels[31-i]
		u, err := strconv.ParseUint(utils.Bytes2StrUnsafe(label), 16, 4)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid label %s: %s", label, err)
		}
		buf[(i / 2)] += byte(u) << ((1 - i%2) * 4)
	}
	return netip.AddrFrom16(buf), nil
}

func (h *RvLookup) saveNameAddr(name dnsmsg.Name, addr netip.Addr) {
	s, ok := h.strCache.Get(utils.Bytes2StrUnsafe(name.Data()))
	if !ok { // concurrent set is possible, but it's ok
		s = string(name.Data())
	}
	h.cache.Set(addr, s)
}
