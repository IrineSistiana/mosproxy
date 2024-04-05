package router

import (
	"errors"
	"fmt"
)

// Reloader is not concurrent safe.
type reloader interface {
	commit()
	discard()
}

var (
	ErrConcurrentReload = errors.New("concurrent reloading call")
)

func (r *Router) Reload() (err error) {
	if !r.reloading.CompareAndSwap(0, 1) {
		return ErrConcurrentReload
	}
	defer r.reloading.Store(0)

	var stagedReloaders []reloader
	stage := func(r reloader) {
		stagedReloaders = append(stagedReloaders, r)
	}
	defer func() { // commit or discard changes
		failed := err != nil
		for _, r := range stagedReloaders {
			if failed {
				r.discard()
			} else {
				r.commit()
			}
		}
	}()

	err = r.cache.reload()
	if err != nil {
		return fmt.Errorf("failed to reload cache, %w", err)
	}
	stage(r.cache)

	for tag, s := range r.domainSets {
		err = s.reload()
		if err != nil {
			return fmt.Errorf("failed to reload domain set [%s], %w", tag, err)
		}
		stage(s)
		r.logger.Info().Str("tag", tag).Strs("files", s.fs).Int("len", s.stagedM.Len()).Msg("new domain set loaded")
	}
	return nil
}
