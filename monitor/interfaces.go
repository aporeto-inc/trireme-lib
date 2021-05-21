package monitor

import (
	"context"

	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/registerer"
)

// A Monitor is an interface implmented to start/stop monitors.
type Monitor interface {

	// Start starts the monitor.
	Run(ctx context.Context) error

	// UpdateConfiguration updates the configuration of the monitor
	UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error

	// Resync requests to the monitor to do a resync.
	Resync(ctx context.Context) error
}

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

	// Resync should resynchronize PUs. This should be done while starting up.
	Resync(ctx context.Context) error
}
