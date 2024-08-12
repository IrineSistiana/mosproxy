package router

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
)

func (r *Router) loadDomainSet(cfg *DomainSetConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("missing tag")
	}
	if _, dup := r.domainSets[cfg.Tag]; dup {
		return fmt.Errorf("dup tag [%s]", cfg.Tag)
	}

	ds := newDomainSet(cfg.Files)
	if err := ds.reload(); err != nil {
		return fmt.Errorf("failed to read data set, %w", err)
	}
	ds.commit()
	r.domainSets[cfg.Tag] = ds
	r.logger.Info().Str("tag", cfg.Tag).Strs("files", cfg.Files).Int("len", ds.m.Load().Len()).Msg("domain set loaded")
	return nil
}

func loadDomainSets(fs []string) (*domainmatcher.Matcher, error) {
	l := domainmatcher.NewLoader()
	for _, fp := range fs {
		f, err := os.Open(fp)
		if err != nil {
			return nil, fmt.Errorf("failed to open domain file %s, %w", fp, err)
		}
		if filepath.Ext(fp) == "mpct" {
			err = l.LoadCompiledTree(f)
		} else {
			err = l.LoadRulesFromReader(f)
		}
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to load data from file %s, %w", fp, err)
		}
	}
	m, err := l.Compile()
	if err != nil {
		return nil, fmt.Errorf("failed to compile data set, %w", err)
	}
	return m, nil
}

func newDomainSet(fs []string) *domainSet {
	s := new(domainSet)
	s.fs = append(s.fs, fs...)
	return s
}

type domainSet struct {
	m atomic.Pointer[domainmatcher.Matcher]

	fs      []string
	stagedM *domainmatcher.Matcher
}

func (s *domainSet) reload() error {
	m, err := loadDomainSets(s.fs)
	if err != nil {
		return err
	}
	s.stagedM = m
	return nil
}

func (s *domainSet) commit() {
	if s.stagedM != nil {
		s.m.Store(s.stagedM)
		s.stagedM = nil
	}
}

func (s *domainSet) discard() {
	if s.stagedM != nil {
		s.m.Store(s.stagedM)
		s.stagedM = nil
	}
}
