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

	var reloaders []Dataloader
	if r.ecsZone != nil {
		reloaders = append(reloaders, r.ecsZone)
	}
	if r.ecsZoneOverwrite != nil {
		reloaders = append(reloaders, r.ecsZoneOverwrite)
	}
	for _, l := range r.domainSets {
		reloaders = append(reloaders, l)
	}

	var stagedReloaders []Dataloader
	ready := func(r Dataloader) {
		stagedReloaders = append(stagedReloaders, r)
	}
	commitAll := func() {
		for _, r := range stagedReloaders {
			r.Commit()
		}
	}
	discardAll := func() {
		for _, r := range stagedReloaders {
			r.Discard()
		}
	}

	for _, l := range reloaders {
		ok := l.LoadAndStage()
		if !ok {
			discardAll()
			return fmt.Errorf("failed to reload %T", l)
		}
		ready(l)
	}
	commitAll()
	return nil
}
