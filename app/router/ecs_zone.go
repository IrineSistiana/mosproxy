package router

import (
	"net/netip"
	"os"

	"github.com/IrineSistiana/mosproxy/internal/ipmarker"
)

func (r *Router) loadEcsZone(f string) error {
	loadFn := func(args string) (*ipmarker.IpMarker, error) {
		f, err := os.Open(args)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		m, err := ipmarker.LoadIpMarkerFromReader(f)
		if err != nil {
			return nil, err
		}
		r.logger.Info().Str("file", args).Int("len", m.IpLen()).Int("zone_num", m.MarkLen()).Msg("ecs ip zone file loaded")
		return m, nil
	}
	l := newDataLoader[string, ipmarker.IpMarker](f, loadFn, nil)
	err := l.loadAndStage()
	if err != nil {
		return err
	}
	l.commit()
	r.ecsZone = l
	return nil
}

type ECSZoneOverWrite struct {
	m map[string]netip.Prefix
}

func (ezo *ECSZoneOverWrite) Get(z string) netip.Prefix {
	return ezo.m[z]
}

func (r *Router) loadEcsZoneOverwrite(f string) error {
	loadFn := func(args string) (*ECSZoneOverWrite, error) {
		f, err := os.Open(args)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		m, err := ipmarker.LoadMark2PrefixFromReader(f)
		if err != nil {
			return nil, err
		}
		r.logger.Info().Str("file", args).Int("len", len(m)).Msg("zone ecs data loaded")
		return &ECSZoneOverWrite{m: m}, nil
	}

	l := newDataLoader[string, ECSZoneOverWrite](f, loadFn, nil)
	err := l.loadAndStage()
	if err != nil {
		return err
	}
	l.commit()
	r.ecsZoneOverwrite = l
	return nil
}
