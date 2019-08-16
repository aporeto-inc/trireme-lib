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

func New() *WindowsMonitor {
	return &WindowsMonitor{
		proc: &windowsProcessor{},
	}
}

func (w *WindowsMonitor) Run(ctx context.Context) error {
	return nil
}
func (w *WindowsMonitor) SetupHandlers(m *config.ProcessorConfig) {
	return
}
func (w *WindowsMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {
	return nil
}
func (w *WindowsMonitor) Resync(ctx context.Context) error {
	return nil
}
