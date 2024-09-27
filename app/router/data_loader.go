package router

import "sync/atomic"

type dataloader interface {
	// Load T and stage the T. Return err if ocurred.
	loadAndStage() error

	// commit the change. If no T staged, this call is noop.
	commit()

	// discard the change. If no T staged, this call is noop.
	discard()
}

// Provider data.
// Do not retain the result of V(), it may change after router reloaded.
type DataProvider[V any] interface {
	V() *V
}

// Funcs of dataloaderImpl are not concurrent safe.
// Except load().
type dataloaderImpl[A, T any] struct {
	args      A
	loadFn    func(args A) (*T, error)
	releaseFn func(args A, v *T)

	v      atomic.Pointer[T]
	staged *T
}

func newDataLoader[A, V any](
	args A, // args that to create the loader in loadFn.
	loadFn func(args A) (*V, error), // load the T. CANNOT be nil.
	releaseFn func(args A, v *V), // Called when old T was swapped. Can be nil.
) *dataloaderImpl[A, V] {
	return &dataloaderImpl[A, V]{
		args:      args,
		loadFn:    loadFn,
		releaseFn: releaseFn,
	}
}

func (s *dataloaderImpl[A, V]) loadAndStage() error {
	_, err := s.loadAndStageV()
	return err
}

func (s *dataloaderImpl[A, V]) loadAndStageV() (*V, error) {
	v, err := s.loadFn(s.args)
	if err != nil {
		return nil, err
	}
	s.staged = v
	return v, nil
}

func (s *dataloaderImpl[A, V]) commit() {
	if s.staged != nil {
		old := s.v.Swap(s.staged)
		s.staged = nil
		if old != nil && s.releaseFn != nil {
			s.releaseFn(s.args, old)
		}
	}
}

func (s *dataloaderImpl[A, V]) discard() {
	if old := s.staged; old != nil && s.releaseFn != nil {
		s.releaseFn(s.args, old)
	}
	s.staged = nil
}

func (s *dataloaderImpl[A, V]) V() *V {
	return s.v.Load()
}
