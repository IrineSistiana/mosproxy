package router

import "sync/atomic"

type Dataloader interface {
	// Load T and stage the T. Return false if error ocurred.
	LoadAndStage() (ok bool)

	// Commit the change. If no T staged, this call is noop.
	Commit()

	// Discard the change. If no T staged, this call is noop.
	Discard()
}

// Provider data.
// Do not retain the result of V(), it may change after router reloaded.
type DataProvider[V any] interface {
	V() *V
}

// Funcs of DataloaderImpl are not concurrent safe.
// Except load().
type DataloaderImpl[T any] struct {
	loadFn    func() (*T, error)
	releaseFn func(v *T)

	v      atomic.Pointer[T]
	staged *T
}

func NewDataLoader[V any](
	loadFn func() (*V, error), // load the T. CANNOT be nil.
	releaseFn func(v *V), // Called when old T was swapped. Can be nil.
) *DataloaderImpl[V] {
	return &DataloaderImpl[V]{
		loadFn:    loadFn,
		releaseFn: releaseFn,
	}
}

func (s *DataloaderImpl[V]) LoadAndStage() (ok bool) {
	_, err := s.LoadAndStageV()
	return err == nil
}

func (s *DataloaderImpl[V]) LoadAndStageV() (*V, error) {
	v, err := s.loadFn()
	if err != nil {
		return nil, err
	}
	s.staged = v
	return v, nil
}

func (s *DataloaderImpl[V]) Commit() {
	if s.staged != nil {
		old := s.v.Swap(s.staged)
		s.staged = nil
		if old != nil && s.releaseFn != nil {
			s.releaseFn(old)
		}
	}
}

func (s *DataloaderImpl[V]) Discard() {
	if old := s.staged; old != nil && s.releaseFn != nil {
		s.releaseFn(old)
	}
	s.staged = nil
}

func (s *DataloaderImpl[V]) V() *V {
	return s.v.Load()
}
