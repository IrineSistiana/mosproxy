package mlog

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	lvl = zap.NewAtomicLevelAt(zap.InfoLevel)
	l   = initLogger()
	s   = l.Sugar()

	nop = zap.NewNop()
)

type lockBufWriteSyncer struct {
	sync.Mutex
	syncTimer *time.Timer
	w         *bufio.Writer
}

func (w *lockBufWriteSyncer) Sync() error {
	w.Lock()
	defer w.Unlock()
	return w.w.Flush()
}

func (w *lockBufWriteSyncer) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()

	defer w.syncTimer.Reset(time.Millisecond * 100)
	return w.w.Write(p)
}

func lockBufWriter(w io.Writer) *lockBufWriteSyncer {
	bw := bufio.NewWriterSize(os.Stderr, 4096)
	return &lockBufWriteSyncer{
		syncTimer: time.AfterFunc(0, func() { bw.Flush() }),
		w:         bw,
	}
}

func initLogger() *zap.Logger {
	var out zapcore.WriteSyncer
	if ok, _ := strconv.ParseBool(os.Getenv("MOSPROXY_BUFFERLOGGER")); ok {
		out = lockBufWriter(os.Stderr)
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
