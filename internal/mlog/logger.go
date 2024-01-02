package mlog

import (
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/delaywriter"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	lvl = zap.NewAtomicLevelAt(zap.InfoLevel)
	l   = initLogger()
	s   = l.Sugar()

	nop = zap.NewNop()
)

func initLogger() *zap.Logger {
	var out zapcore.WriteSyncer
	if ok, _ := strconv.ParseBool(os.Getenv("MOSPROXY_BUFFERLOGGER")); ok {
		opts := delaywriter.Opts{
			BufSize: 4096,
			Delay:   time.Millisecond * 10,
		}
		out = delaywriter.New(os.Stderr, opts)
	} else {
		out = zapcore.Lock(os.Stderr)
	}

	var logger *zap.Logger
	if ok, _ := strconv.ParseBool(os.Getenv("MOSPROXY_JSONLOGGER")); ok {
		logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), out, lvl))
	} else {
		logger = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), out, lvl))
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
