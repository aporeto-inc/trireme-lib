// +build windows

package monitor

import (
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
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

// OptionMonitorWindowsProcess provides a way to add a linux process monitor and related configuration to be used with New().
func OptionMonitorWindowsProcess(
	opts ...WindowsMonitorOption,
) Options {
	return optionMonitorWindows(false, opts...)
}

// SubOptionMonitorWindowsExtractor provides a way to specify metadata extractor for linux monitors.
func SubOptionMonitorWindowsExtractor(extractor extractors.EventMetadataExtractor) WindowsMonitorOption {
	return func(cfg *windowsmonitor.Config) {
		cfg.EventMetadataExtractor = extractor
	}
}

// optionMonitorWindows provides a way to add a linux monitor and related configuration to be used with New().
func optionMonitorWindows(host bool,
	opts ...WindowsMonitorOption,
) Options {
	wc := windowsmonitor.DefaultConfig(host)
	// Collect all docker options
	for _, opt := range opts {
		opt(wc)
	}
	return func(cfg *config.MonitorConfig) {
		if host {
			cfg.Monitors[config.LinuxHost] = wc
		} else {
			cfg.Monitors[config.LinuxProcess] = wc
		}
	}
}

func SubOptionWindowsHostMode(host bool) WindowsMonitorOption {
	return func(cfg *windowsmonitor.Config) {
		cfg.Host = host
	}
}
