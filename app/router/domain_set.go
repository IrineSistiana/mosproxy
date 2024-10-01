package router

import (
	"errors"
	"fmt"
	"os"

	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
)

func (r *Router) loadDomainSet(cfg *DomainSetConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("missing tag")
	}
	if _, dup := r.domainSets[cfg.Tag]; dup {
		return fmt.Errorf("dup tag [%s]", cfg.Tag)
	}

	loadFiles := func(fps []string) (*domainmatcher.Matcher, error) {
		loader := domainmatcher.NewLoader()
		for _, fp := range fps {
			f, err := os.Open(fp)
			if err != nil {
				return nil, fmt.Errorf("failed to open domain file %s, %w", fp, err)
			}
			err = loader.LoadRulesFromReader(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to load data from file %s, %w", fp, err)
			}
		}
		m, err := loader.Compile()
		if err != nil {
			return nil, fmt.Errorf("failed to compile data set, %w", err)
		}
		return m, err
	}
	loadFn := func() (*domainmatcher.Matcher, error) {
		m, err := loadFiles(cfg.Files)
		if err != nil {
			r.logger.Error().Str("tag", cfg.Tag).Strs("files", cfg.Files).Msg("failed to load domain set")
			return nil, err
		}
		r.logger.Info().Str("tag", cfg.Tag).Strs("files", cfg.Files).Int("len", m.Len()).Msg("domain set loaded")
		return m, nil
	}

	l := NewDataLoader(loadFn, nil)
	_, err := l.LoadAndStageV()
	if err != nil {
		return err
	}
	l.Commit()
	r.domainSets[cfg.Tag] = l
	return nil
}
