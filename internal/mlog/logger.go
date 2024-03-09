package mlog

import (
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/rs/zerolog"
)

var (
	l   = initLogger()
	nop = zerolog.Nop()
)

func SetLvl(lvl zerolog.Level) {
	zerolog.SetGlobalLevel(lvl)
}

func initLogger() zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	var w io.Writer
	if ok, _ := strconv.ParseBool(os.Getenv("MOSPROXY_JSONLOGGER")); ok {
		w = lock(os.Stderr)
	} else {
		w = zerolog.NewConsoleWriter()
	}

	l := zerolog.New(w).With().Timestamp().Logger()

	// Redirect std log
	redirectWriter := WriteToLogger(l, "redirected std log", "data")
	log.SetFlags(0) // disable time/date
	log.SetPrefix("")
	log.SetOutput(redirectWriter)

	// quic warning, we don't need this.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
	return l
}

func Nop() *zerolog.Logger {
	return &nop
}

func L() *zerolog.Logger {
	return &l
}

func WriteToLogger(to zerolog.Logger, msg string, key string) io.Writer {
	return &logCatcher{
		logger: to.With().CallerWithSkipFrameCount(1).Logger(),
		msg:    msg,
		key:    key}
}

type logCatcher struct {
	logger zerolog.Logger
	msg    string
	key    string
}

func (w *logCatcher) Write(b []byte) (int, error) {
	b = bytes.TrimSpace(b) // trim \n from std logger
	w.logger.Log().Bytes(w.key, b).Msg(w.msg)
	return len(b), nil
}

type safeWriter struct {
	m sync.Mutex
	w io.Writer
}

func lock(w io.Writer) io.Writer {
	return &safeWriter{
		w: w,
	}
}

func (w *safeWriter) Write(b []byte) (int, error) {
	w.m.Lock()
	defer w.m.Unlock()
	return w.w.Write(b)
}
