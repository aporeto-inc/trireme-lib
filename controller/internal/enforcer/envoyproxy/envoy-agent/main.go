package main

import (
	"os"

	"github.com/spf13/cobra"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyproxy/sds"
	"go.uber.org/zap"
	"istio.io/istio/pkg/cmd"
)

var (
	sdsOptions sds.Options
	rootCmd    = &cobra.Command{
		Use:   "nodeagent",
		Short: "envoy-trireme agent",
		RunE: func(c *cobra.Command, args []string) error {

			stop := make(chan struct{})

			server := sds.NewServer()

			server.CreateSdsService(&sdsOptions)

			defer server.Stop()
			zap.L().Debug("Started the envoy-trireme proxy")
			cmd.WaitSignal(stop)

			return nil
		},
	}
)

func main() {
	rootCmd.PersistentFlags().StringVar(&sdsOptions.SocketPath, "workloadUDSPath",
		"/var/run/sds/uds_path", "Unix domain socket through which SDS server communicates with envoy proxies")
	if err := rootCmd.Execute(); err != nil {
		zap.L().Error("Cannot execute the envoy-agent", zap.Error(err))
		os.Exit(1)
	}
}
