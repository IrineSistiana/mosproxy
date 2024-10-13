package router

import (
	"crypto/sha256"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
)

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

// Funcs of fileLoader are not concurrent safe.
// Except V().
type fileLoader[V any] struct {
	fp      string
	parseFn func(b []byte) (*V, error)
	logger  *zerolog.Logger
	vInfo   func(e *zerolog.Event, v *V) // print log fields when v is loaded, DO NOT call e.Msg().

	hash       [sha256.Size]byte
	v          atomic.Pointer[V]
	stagedHash [sha256.Size]byte
	staged     *V
}

func (s *fileLoader[V]) LoadAndStage() (ok bool) {
	b, err := os.ReadFile(s.fp)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to read file")
		return
	}
	newHash := sha256.Sum256(b)
	if newHash == s.hash {
		s.logger.Info().Msg("skip loading file, same checksum")
		return true
	}
	v, err := s.parseFn(b)
	if v != nil {
		e := s.logger.Info()
		if s.vInfo != nil {
			s.vInfo(e, v)
		}
		e.Msg("file loaded")
		s.staged = v
		s.stagedHash = newHash
	}
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to parse data")
	}
	return err == nil
}

func (s *fileLoader[V]) init() (*V, error) {
	b, err := os.ReadFile(s.fp)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	v, err := s.parseFn(b)
	if err != nil {
		return v, err
	}
	s.v.Store(v)
	s.hash = h
	return v, nil
}

func (s *fileLoader[V]) Commit() {
	if s.staged != nil {
		s.v.Store(s.staged)
		s.hash = s.stagedHash
		s.staged = nil
		clear(s.hash[:])
	}
}

func (s *fileLoader[V]) Discard() {
	s.staged = nil
	clear(s.hash[:])
}

func (s *fileLoader[V]) V() *V {
	return s.v.Load()
}

type fileLoaderGroup[V any] []*fileLoader[V]

func (g fileLoaderGroup[V]) LoadAndStage() bool {
	for _, loader := range g {
		ok := loader.LoadAndStage()
		if !ok {
			return false
		}
	}
	return true
}

func (g fileLoaderGroup[V]) Commit() {
	for _, loader := range g {
		loader.Commit()
	}
}

func (g fileLoaderGroup[V]) Discard() {
	for _, loader := range g {
		loader.Discard()
	}
}
