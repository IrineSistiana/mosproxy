package app

import (
	"fmt"
	"net"
	"runtime"

	"net/http"
	_ "net/http/pprof"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	rootCmd *cobra.Command
)

var (
	logger = mlog.L()
)

func init() {
	rootCmd = &cobra.Command{}
	logLvl := rootCmd.PersistentFlags().String("log-lvl", "info", "log level [fatal|error|warn|info|debug]")
	GOMAXPROCS := rootCmd.PersistentFlags().Int("gomaxprocs", 0, "set runtime.GOMAXPROCS()")
	pprofServer := rootCmd.PersistentFlags().String("pprof", "", "start golang pprof endpoint at this address")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if *GOMAXPROCS > 0 {
			runtime.GOMAXPROCS(*GOMAXPROCS)
		}
		lvl, err := zapcore.ParseLevel(*logLvl)
		if err != nil {
			return fmt.Errorf("invalid log lvl [%s]. %w", *logLvl, err)
		}
		mlog.SetLevel(lvl)

		if len(*pprofServer) > 0 {
			l, err := net.Listen("tcp", *pprofServer)
			if err != nil {
				logger.Fatal("failed to listen pprof server socket", zap.Error(err))
			}
			logger.Info("pprof server started", zap.Stringer("addr", l.Addr()))
			go func() {
				defer l.Close()
				err := http.Serve(l, nil)
				logger.Fatal("pprof server exited", zap.Error(err))
			}()
		}
		return nil
	}
}

func RootCmd() *cobra.Command {
	return rootCmd
}
