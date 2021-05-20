// +build windows

package windowsmonitor

import "go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
	Host                   bool
}

// DefaultConfig provides a default configuration
func DefaultConfig(host bool) *Config {
	return &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
		Host:                   host,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(windowsConfig *Config) *Config {

	defaultConfig := DefaultConfig(windowsConfig.Host)
	if windowsConfig.EventMetadataExtractor == nil {
		windowsConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}
	return windowsConfig
}
