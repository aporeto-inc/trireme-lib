package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyproxy/sds"
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
			fmt.Println("create and run the sds server")
			server.CreateSdsService(&sdsOptions)

			defer server.Stop()
			fmt.Println("wait for the cmd to finsih")
			cmd.WaitSignal(stop)
			fmt.Println("evoy-trireme is done running")

			return nil
		},
	}
)

func main() {
	rootCmd.PersistentFlags().StringVar(&sdsOptions.SocketPath, "workloadUDSPath",
		"/var/run/sds/uds_path", "Unix domain socket through which SDS server communicates with envoy proxies")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Cannot execute the envoy-agent")
		os.Exit(1)
	}
}
