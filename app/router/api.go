package router

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (r *Router) initApiServer(cfg *APIConfig) error {
	addr := cfg.Addr
	if len(addr) == 0 {
		return nil
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.logger.Info().Stringer("addr", l.Addr()).Msg("api server started")

	mux := r.apiMux

	metricsHandler := promhttp.HandlerFor(r.metricsReg, promhttp.HandlerOpts{})
	mux.Get("/metrics", func(w http.ResponseWriter, req *http.Request) {
		metricsHandler.ServeHTTP(w, req)
	})

	mux.Route("/ctl", func(route chi.Router) {
		route.Get("/reload", func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			r.logger.Info().Object("request", (*httpReqLoggerObj)(req)).Msg("reloading files")
			err := r.Reload()
			if err != nil {
				r.logger.Error().Object("request", (*httpReqLoggerObj)(req)).Err(err).Msg("reload cmd failed")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
			w.Write([]byte("ok"))
			r.logger.Info().
				Object("request", (*httpReqLoggerObj)(req)).
				Dur("elapse", time.Since(start)).
				Msg("files reloaded")
		})
	})

	s := http.Server{
		Handler: mux,
	}
	r.serverClosers = append(r.serverClosers, func() { s.Close() })
	go func() {
		err := s.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			r.Close(fmt.Errorf("api endpoint exited, %w", err))
		}
	}()
	return nil
}
