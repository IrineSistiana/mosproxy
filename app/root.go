package app

import (
	"fmt"
	"net"
	"runtime"

	"net/http"
	_ "net/http/pprof"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
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
		lvl, err := zerolog.ParseLevel(*logLvl)
		if err != nil {
			return fmt.Errorf("invalid log lvl [%s]. %w", *logLvl, err)
		}
		mlog.SetLvl(lvl)

		if len(*pprofServer) > 0 {
			l, err := net.Listen("tcp", *pprofServer)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to listen pprof server socket")
			}
			logger.Info().Stringer("addr", l.Addr()).Msg("pprof server started")
			go func() {
				defer l.Close()
				err := http.Serve(l, nil)
				logger.Fatal().Err(err).Msg("pprof server exited")
			}()
		}
		return nil
	}
}

func RootCmd() *cobra.Command {
	return rootCmd
}
