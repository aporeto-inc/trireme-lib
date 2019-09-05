package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.aporeto.io/istio/istio/pkg/cmd"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyproxy/sds"
)

var (
	rootCmd = &cobra.Command{
		Use:   "envoyagent",
		Short: "envoy-trireme agent",
		RunE: func(c *cobra.Command, args []string) error {

			stop := make(chan struct{})

			server := sds.NewServer()

			defer server.Stop()

			cmd.WaitSignal(stop)

			return nil
		},
	}
)

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Cannot execute the envoy-agent")
		os.Exit(1)
	}
}
