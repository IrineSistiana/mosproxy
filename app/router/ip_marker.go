package router

import (
	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"github.com/IrineSistiana/mosproxy/internal/netlist"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// TODO: ip marker bin maybe useless, remove it.
func newConvIpMarkerCmd() *cobra.Command {
	var (
		in, out string
	)
	cmd := &cobra.Command{
		Use:   "conv-ipmarker",
		Short: "Convert an ip marker file to a bin format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			convIpMarker(in, out)
		},
	}
	cmd.Flags().StringVarP(&in, "input", "i", "", "input txt file")
	cmd.Flags().StringVarP(&out, "out", "o", "ip_marker.bin", "output bin file")
	cmd.MarkFlagRequired("input")
	return cmd
}

func convIpMarker(in, out string) {
	logger := mlog.L()
	logger.Info("reading txt ip marker file", zap.String("file", in))
	list, _, err := loadIpMarkerFromFile(in)
	if err != nil {
		logger.Fatal("failed to load ip marker", zap.Error(err))
	}
	logger.Info("ip marker file loaded", zap.Int("length", list.Len()))
	logger.Info("saving ip marker bin file", zap.String("file", out))
	err = netlist.SaveIpMarkerBin(out, list)
	if err != nil {
		logger.Fatal("failed to save ip marker bin", zap.Error(err))
	}
	logger.Info("ip marker bin file saved", zap.Error(err))
}
