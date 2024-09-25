package router

import (
	"fmt"

	"github.com/IrineSistiana/mosproxy/app/router/loader"
	domainmatcher "github.com/IrineSistiana/mosproxy/internal/domain_matcher"
)

type rule struct {
	reverse  bool
	matcher  *loader.Loader[[]string, domainmatcher.Matcher]
	reject   uint16
	upstream Upstream // maybe nil
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
		uw := r.upstreams[cfg.Forward]
		if uw != nil {
			ru.upstream = uw
		} else {
			lb := r.loadBalancers[cfg.Forward]
			if lb != nil {
				ru.upstream = lb
			} else {
				return nil, fmt.Errorf("unknown forward target [%s]", cfg.Forward)
			}
		}
	}
	return ru, nil
}
