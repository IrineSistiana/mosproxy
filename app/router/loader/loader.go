package loader

import "sync/atomic"

type Reloader interface {
	// Load T and stage the T. Return err if ocurred.
	LoadAndStage() error

	// Commit the change. If no T staged, this call is noop.
	Commit()

	// Discard the change. If no T staged, this call is noop.
	Discard()
}

// Funcs of Loader are not concurrent safe.
// Except load().
type Loader[A, T any] struct {
	args      A
	loadFn    func(args A) (*T, error)
	releaseFn func(args A, v *T)

	v      atomic.Pointer[T]
	staged *T
}

func NewLoader[A, T any](
	args A, // args that to create the loader in loadFn.
	loadFn func(args A) (*T, error), // load the T. CANNOT be nil.
	releaseFn func(args A, v *T), // Called when old T was swapped. Can be nil.
) *Loader[A, T] {
	return &Loader[A, T]{
		args:      args,
		loadFn:    loadFn,
		releaseFn: releaseFn,
	}
}

func (s *Loader[A, T]) LoadAndStage() error {
	_, err := s.LoadAndStageV()
	return err
}

func (s *Loader[A, T]) LoadAndStageV() (*T, error) {
	v, err := s.loadFn(s.args)
	if err != nil {
		return nil, err
	}
	s.staged = v
	return v, nil
}

func (s *Loader[A, T]) Commit() {
	if s.staged != nil {
		old := s.v.Swap(s.staged)
		s.staged = nil
		if old != nil && s.releaseFn != nil {
			s.releaseFn(s.args, old)
		}
	}
}

func (s *Loader[A, T]) Discard() {
	if old := s.staged; old != nil && s.releaseFn != nil {
		s.releaseFn(s.args, old)
	}
	s.staged = nil
}

func (s *Loader[A, T]) V() *T {
	return s.v.Load()
}
