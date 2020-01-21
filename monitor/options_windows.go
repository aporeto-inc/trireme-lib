// +build windows

package monitor

import (
	"go.aporeto.io/trireme-lib/monitor/config"
	windowsmonitor "go.aporeto.io/trireme-lib/monitor/internal/windows"
)

// WindowsMonitorOption is provided using functional arguments
type WindowsMonitorOption func(*windowsmonitor.Config)

// OptionMonitorWindows provides a way to add a linux monitor and related configuration to be used with New().
func OptionMonitorWindows(
	opts ...WindowsMonitorOption,
) Options {
	return optionMonitorWindows(true, opts...)
}

// optionMonitorWindows provides a way to add a linux monitor and related configuration to be used with New().
func optionMonitorWindows(host bool,
	opts ...WindowsMonitorOption,
) Options {
	wc := windowsmonitor.DefaultConfig(true)
	// Collect all docker options
	for _, opt := range opts {
		opt(wc)
	}
	return func(cfg *config.MonitorConfig) {
		if host {
			cfg.Monitors[config.LinuxHost] = wc
		} else {
			cfg.Monitors[config.Windows] = wc
		}
	}
}

func SubOptionWindowsHostMode(host bool) WindowsMonitorOption {
	return func(cfg *windowsmonitor.Config) {
		cfg.Host = host
	}
}
