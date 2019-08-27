// +build windows

package windowsmonitor

import (
	"context"
	"fmt"
	"regexp"

	"go.aporeto.io/trireme-lib/common"
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
	if err := w.proc.config.IsComplete(); err != nil {
		return fmt.Errorf("linux %t: %s", w.proc.host, err)
	}

	return w.Resync(ctx)

}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (w *WindowsMonitor) SetupHandlers(m *config.ProcessorConfig) {
	w.proc.config = m
	return
}

// SetupConfig sets up the config for the monitor
func (w *WindowsMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {
	if cfg == nil {
		cfg = DefaultConfig(false)
	}
	windowsConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}
	if registerer != nil {
		if err := registerer.RegisterProcessor(common.HostPU, w.proc); err != nil {
			return err
		}
		if err := registerer.RegisterProcessor(common.HostNetworkPU, w.proc); err != nil {
			return err
		}

	}
	windowsConfig = SetupDefaultConfig(windowsConfig)
	w.proc.host = windowsConfig.Host
	w.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_]{1,11}$")
	w.proc.metadataExtractor = windowsConfig.EventMetadataExtractor
	if w.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}
	return nil
}

// Resync instructs the monitor to do a resync.
func (w *WindowsMonitor) Resync(ctx context.Context) error {
	return w.proc.Resync(ctx, nil)
}
