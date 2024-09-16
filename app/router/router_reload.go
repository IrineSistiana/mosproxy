package router

import (
	"errors"
	"fmt"

	"github.com/IrineSistiana/mosproxy/app/router/loader"
)

var (
	ErrConcurrentReload = errors.New("concurrent reloading call")
)

func (r *Router) Reload() (err error) {
	if !r.reloading.CompareAndSwap(0, 1) {
		return ErrConcurrentReload
	}
	defer r.reloading.Store(0)

	var stagedReloaders []loader.Reloader
	ready := func(r loader.Reloader) {
		stagedReloaders = append(stagedReloaders, r)
	}
	failed := false

	defer func() { // commit or discard changes
		for _, r := range stagedReloaders {
			if failed {
				r.Discard()
			} else {
				r.Commit()
			}
		}
	}()

	if loader := r.ecsZone; loader != nil {
		err := loader.LoadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload , %w", err)
		}
		ready(loader)
	}

	if loader := r.ecsZoneOverwrite; loader != nil {
		err := loader.LoadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload ecs overwrite rules, %w", err)
		}
		ready(loader)
	}

	for tag, loader := range r.domainSets {
		err := loader.LoadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload domain set [%s], %w", tag, err)
		}
		ready(loader)
	}
	return nil
}
