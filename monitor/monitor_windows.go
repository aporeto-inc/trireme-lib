// +build windows

package monitor

import (
	"context"

	"go.aporeto.io/trireme-lib/monitor/config"
)

// Run starts the monitor.
func Run(ctx context.Context) error {
	return nil
}

// UpdateConfiguration updates the configuration of the monitor
func UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error {
	return nil
}

// Resync requests to the monitor to do a resync.
func Resync(ctx context.Context) error {
	return nil
}
