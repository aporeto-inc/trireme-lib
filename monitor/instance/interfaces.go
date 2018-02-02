package monitorinstance

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
)

// Implementation for a monitor.
type Implementation interface {

	// Run starts the monitor implementation.
	Run(ctx context.Context) error

	// SetupConfig provides a configuration to implmentations. Every implmentation
	// can have its own config type.
	SetupConfig(registerer registerer.Registerer, cfg interface{}) error

	// SetupHandlers sets up handlers for monitors to invoke for various events such as
	// processing unit events and synchronization events. This will be called before Start()
	// by the consumer of the monitor
	SetupHandlers(c *config.ProcessorConfig)

	// ReSync should resynchronize PUs. This should be done while starting up.
	ReSync(ctx context.Context) error
}
