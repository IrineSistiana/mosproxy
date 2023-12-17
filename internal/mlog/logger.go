package mlog

import (
	"bytes"
	"io"
	"log"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	stderr = zapcore.Lock(os.Stderr)
	lvl    = zap.NewAtomicLevelAt(zap.InfoLevel)
	l      = initLogger()
	s      = l.Sugar()

	nop = zap.NewNop()
)

func initLogger() *zap.Logger {
	var logger *zap.Logger
	if _, ok := os.LookupEnv("MOSPROXY_JSONLOGGER"); ok {
		logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), stderr, lvl))
	} else {
		logger = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), stderr, lvl))
	}

	// Redirect std log
	w := WriteToLogger(logger, zap.InfoLevel, "redirect std log", "data")
	log.SetFlags(0) // disable time/date
	log.SetPrefix("")
	log.SetOutput(w)

	// quic warning, we don't need this.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
	return logger
}

func L() *zap.Logger {
	return l
}

func SetLevel(l zapcore.Level) {
	lvl.SetLevel(l)
}
func Lvl() zapcore.Level {
	return l.Level()
}

func S() *zap.SugaredLogger {
	return s
}

func Nop() *zap.Logger {
	return nop
}

func WriteToLogger(to *zap.Logger, lvl zapcore.Level, msg string, key string) io.Writer {
	to = to.WithOptions(zap.AddCallerSkip(3)) // Skip log.Logger's stack. This value is copied from zap.RedirectStdLog()
	return &logCatcher{logger: to, lvl: lvl, msg: msg, key: key}
}

type logCatcher struct {
	logger *zap.Logger
	lvl    zapcore.Level
	msg    string
	key    string
}

func (w *logCatcher) Write(b []byte) (int, error) {
	b = bytes.TrimSpace(b)
	w.logger.Check(w.lvl, w.msg).Write(zap.ByteString(w.key, b))
	return len(b), nil
}
