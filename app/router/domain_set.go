package router

import (
	"errors"
	"fmt"
	"os"

	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
)

func (r *router) loadDomainSet(cfg *DomainSetConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("missing tag")
	}
	if _, dup := r.domainSets[cfg.Tag]; dup {
		return fmt.Errorf("dup tag [%s]", cfg.Tag)
	}

	m := domainmatcher.NewMixMatcher()
	for _, fp := range cfg.Files {
		f, err := os.Open(fp)
		if err != nil {
			return fmt.Errorf("failed to open domain file %s, %w", fp, err)
		}
		err = domainmatcher.LoadMixMatcherFromReader(m, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("failed to load data, %w", err)
		}
		r.logger.Info().Str("tag", cfg.Tag).Str("file", fp).Msg("domain file loaded")
	}
	r.logger.Info().Str("tag", cfg.Tag).Int("rules", m.Len()).Msg("domain set loaded")
	r.domainSets[cfg.Tag] = m
	return nil
}
