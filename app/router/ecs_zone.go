package router

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/ipmarker"
	"github.com/rs/zerolog"
)

func (r *Router) loadEcsZone(fps []string) error {
	parseFn := func(b []byte) (*ipmarker.IpMarker, error) {
		return ipmarker.LoadIpMarkerFromReader(bytes.NewReader(b))
	}
	vInfo := func(e *zerolog.Event, v *ipmarker.IpMarker) {
		e.Int("ip_len", v.IpLen()).Int("zone_len", v.MarkLen())
	}
	s := make([]*fileLoader[ipmarker.IpMarker], 0)
	for _, fp := range fps {
		logger := r.logger.With().Str("ecs_zone", fp).Logger()
		loader := &fileLoader[ipmarker.IpMarker]{
			fp:      fp,
			parseFn: parseFn,
			logger:  &logger,
			vInfo:   vInfo,
		}
		_, err := loader.init()
		if err != nil {
			return fmt.Errorf("failed to load ecs zone from file %s, %w", fp, err)
		}
		s = append(s, loader)
	}
	r.ecsZone = &ECSZone{fileLoaderGroup: s}
	return nil
}

type ECSZone struct {
	fileLoaderGroup[ipmarker.IpMarker]
}

func (z *ECSZone) Mark(addr netip.Addr) (string, bool) {
	for _, loader := range z.fileLoaderGroup {
		s, ok := loader.V().Mark(addr)
		if ok {
			return s, true
		}
	}
	return "", false
}

type ECSZoneOverWrite struct {
	fileLoaderGroup[map[string]netip.Prefix]
}

func (g *ECSZoneOverWrite) Get(z string) (netip.Prefix, bool) {
	for _, loader := range g.fileLoaderGroup {
		m := loader.V()
		if m != nil {
			p, ok := (*m)[z]
			if ok {
				return p, true
			}
		}
	}
	return netip.Prefix{}, false
}

func (r *Router) loadEcsZoneOverwrite(fps []string) error {
	parseFn := func(b []byte) (*map[string]netip.Prefix, error) {
		m, err := ipmarker.LoadMark2PrefixFromReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return &m, nil
	}
	vInfo := func(e *zerolog.Event, v *map[string]netip.Prefix) {
		e.Int("len", len(*v))
	}
	s := make([]*fileLoader[map[string]netip.Prefix], 0)
	for _, fp := range fps {
		logger := r.logger.With().Str("ecs_zone_overwrite", fp).Logger()
		loader := &fileLoader[map[string]netip.Prefix]{
			fp:      fp,
			parseFn: parseFn,
			logger:  &logger,
			vInfo:   vInfo,
		}
		_, err := loader.init()
		if err != nil {
			return fmt.Errorf("failed to load ecs zone overwrite from file %s, %w", fp, err)
		}
		s = append(s, loader)
	}
	r.ecsZoneOverwrite = &ECSZoneOverWrite{fileLoaderGroup: s}
	return nil
}
