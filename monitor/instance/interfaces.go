package monitorinstance

import (
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
)

// Implementation for a monitor.
type Implementation interface {

	// Start starts the monitor implementation.
	Start() error

	// Stop Stops the monitor implementation.
	Stop() error

	// SetupConfig provides a configuration to implmentations. Every implmentation
	// can have its own config type.
	SetupConfig(registerer registerer.Registerer, cfg interface{}) error

	// SetupHandlers sets up handlers for monitors to invoke for various events such as
	// processing unit events and synchronization events. This will be called before Start()
	// by the consumer of the monitor
	SetupHandlers(c *processor.Config)

	// ReSync should resynchronize PUs. This should be done while starting up.
	ReSync() error
}
