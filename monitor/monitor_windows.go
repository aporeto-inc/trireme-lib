// +build windows

package monitor

import (
	"context"

	"go.aporeto.io/trireme-lib/monitor/config"
)

type monitors struct {
	config   *config.MonitorConfig
	monitors map[config.Type]Implementation
}

// Run starts the monitor.
func (m *monitors) Run(ctx context.Context) error {
	return nil
}

// UpdateConfiguration updates the configuration of the monitor
func (m *monitors) UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error {
	return nil
}

// Resync requests to the monitor to do a resync.
func (m *monitors) Resync(ctx context.Context) error {
	return nil
}

// NewMonitors instantiates all/any combination of monitors supported.
func NewMonitors(opts ...Options) (Monitor, error) {
	return &monitors{}, nil

}
