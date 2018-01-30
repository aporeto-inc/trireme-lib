package monitor

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/monitor/config"
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
