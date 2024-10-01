package router

import (
	"net/netip"
	"os"

	"github.com/IrineSistiana/mosproxy/internal/ipmarker"
)

func (r *Router) loadEcsZone(fp string) error {
	loadFile := func(fp string) (*ipmarker.IpMarker, error) {
		f, err := os.Open(fp)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return ipmarker.LoadIpMarkerFromReader(f)
	}
	loadFn := func() (*ipmarker.IpMarker, error) {
		m, err := loadFile(fp)
		if err != nil {
			r.logger.Error().Str("file", fp).Msg("failed to load ecs ip zone file")
			return nil, err
		}
		r.logger.Info().Str("file", fp).Int("len", m.IpLen()).Int("zone_num", m.MarkLen()).Msg("ecs ip zone file loaded")
		return m, nil
	}
	l := NewDataLoader[ipmarker.IpMarker](loadFn, nil)
	_, err := l.LoadAndStageV()
	if err != nil {
		return err
	}
	l.Commit()
	r.ecsZone = l
	return nil
}

type ECSZoneOverWrite struct {
	m map[string]netip.Prefix
}

func (ezo *ECSZoneOverWrite) Get(z string) netip.Prefix {
	return ezo.m[z]
}

func (r *Router) loadEcsZoneOverwrite(fp string) error {
	loadFile := func(fp string) (map[string]netip.Prefix, error) {
		f, err := os.Open(fp)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return ipmarker.LoadMark2PrefixFromReader(f)
	}
	loadFn := func() (*ECSZoneOverWrite, error) {
		m, err := loadFile(fp)
		if err != nil {
			r.logger.Error().Str("file", fp).Err(err).Msg("failed to load zone ecs overwrite data")
			return nil, err
		}
		r.logger.Info().Str("file", fp).Int("len", len(m)).Msg("zone ecs overwrite loaded")
		return &ECSZoneOverWrite{m: m}, nil
	}

	l := NewDataLoader[ECSZoneOverWrite](loadFn, nil)
	_, err := l.LoadAndStageV()
	if err != nil {
		return err
	}
	l.Commit()
	r.ecsZoneOverwrite = l
	return nil
}
