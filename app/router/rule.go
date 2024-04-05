package router

import (
	"fmt"
)

type rule struct {
	reverse  bool
	matcher  *domainSet
	reject   uint16
	upstream *upstreamWrapper // maybe nil
}

func (r *Router) loadRule(cfg *RuleConfig) (*rule, error) {
	ru := new(rule)
	if len(cfg.Domain) > 0 {
		m := r.domainSets[cfg.Domain]
		if m == nil {
			return nil, fmt.Errorf("cannot find domain set tag [%s]", cfg.Domain)
		}
		ru.matcher = m
		ru.reverse = cfg.Reverse
	}

	ru.reject = cfg.Reject

	if len(cfg.Forward) > 0 {
		u := r.upstreams[cfg.Forward]
		if u == nil {
			return nil, fmt.Errorf("cannot find upstream [%s]", cfg.Forward)
		}
		ru.upstream = u
	}
	return ru, nil
}
