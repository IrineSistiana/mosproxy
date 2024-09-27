package router

import (
	"errors"
	"fmt"
)

var (
	ErrConcurrentReload = errors.New("concurrent reloading call")
)


func (r *Router) Reload() (err error) {
	if !r.reloading.CompareAndSwap(0, 1) {
		return ErrConcurrentReload
	}
	defer r.reloading.Store(0)

	var stagedReloaders []dataloader
	ready := func(r dataloader) {
		stagedReloaders = append(stagedReloaders, r)
	}
	failed := false

	defer func() { // commit or discard changes
		for _, r := range stagedReloaders {
			if failed {
				r.discard()
			} else {
				r.commit()
			}
		}
	}()

	if loader := r.ecsZone; loader != nil {
		err := loader.loadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload , %w", err)
		}
		ready(loader)
	}

	if loader := r.ecsZoneOverwrite; loader != nil {
		err := loader.loadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload ecs overwrite rules, %w", err)
		}
		ready(loader)
	}

	for tag, loader := range r.domainSets {
		err := loader.loadAndStage()
		if err != nil {
			failed = true
			return fmt.Errorf("failed to reload domain set [%s], %w", tag, err)
		}
		ready(loader)
	}
	return nil
}
