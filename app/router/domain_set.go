package router

import (
	"bytes"
	"errors"
	"fmt"

	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/rs/zerolog"
)

func (r *Router) loadDomainSet(cfg *DomainSetConfig) error {
	if len(cfg.Tag) == 0 {
		return errors.New("missing tag")
	}
	if _, dup := r.domainSets[cfg.Tag]; dup {
		return fmt.Errorf("dup tag [%s]", cfg.Tag)
	}

	parseFn := func(b []byte) (*domainmatcher.Matcher, error) {
		loader := domainmatcher.NewLoader()
		err := loader.LoadRulesFromReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("failed to read rules, %w", err)
		}
		m, err := loader.Compile()
		if err != nil {
			return nil, fmt.Errorf("failed to compile dataset, %w", err)
		}
		return m, nil
	}
	vInfo := func(e *zerolog.Event, v *domainmatcher.Matcher) {
		e.Int("rule_num", v.Len())
	}
	s := make([]*fileLoader[domainmatcher.Matcher], 0)
	for _, fp := range cfg.Files {
		logger := r.logger.With().Str("domain_set", cfg.Tag).Str("file", fp).Logger()
		loader := &fileLoader[domainmatcher.Matcher]{
			fp:      fp,
			parseFn: parseFn,
			logger:  &logger,
			vInfo:   vInfo,
		}
		_, err := loader.init()
		if err != nil {
			return fmt.Errorf("failed to load domain set from file %s, %w", fp, err)
		}
		s = append(s, loader)
	}
	r.domainSets[cfg.Tag] = &DomainSet{fileLoaderGroup: s}
	return nil
}

type DomainSet struct {
	fileLoaderGroup[domainmatcher.Matcher]
}

func (g *DomainSet) Match(name dnsmsg.Name) bool {
	for _, loader := range g.fileLoaderGroup {
		ok := loader.V().Match(name)
		if ok {
			return true
		}
	}
	return false
}
