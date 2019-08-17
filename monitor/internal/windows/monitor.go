// +build windows

package windowsmonitor

import (
	"context"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/registerer"
)

// WindowsMonitor hold state for the windows monitor
type WindowsMonitor struct {
	proc *windowsProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() *WindowsMonitor {
	return &WindowsMonitor{
		proc: &windowsProcessor{},
	}
}

// Run implements Implementation interface
func (w *WindowsMonitor) Run(ctx context.Context) error {
	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (w *WindowsMonitor) SetupHandlers(m *config.ProcessorConfig) {
	return
}

// SetupConfig sets up the config for the monitor
func (w *WindowsMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {
	return nil
}

// Resync instructs the monitor to do a resync.
func (w *WindowsMonitor) Resync(ctx context.Context) error {
	return nil
}
