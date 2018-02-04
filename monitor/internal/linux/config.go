package linuxmonitor

import (
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
	ReleasePath            string
	Host                   bool
}

// DefaultConfig provides a default configuration
func DefaultConfig(host bool) *Config {

	if host {
		return &Config{
			EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
			ReleasePath:            "/var/lib/aporeto/cleaner",
			Host:                   host,
		}
	}

	return &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
		ReleasePath:            "/var/lib/aporeto/cleaner",
		Host:                   host,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(linuxConfig *Config) *Config {

	defaultConfig := DefaultConfig(linuxConfig.Host)

	if linuxConfig.ReleasePath == "" {
		linuxConfig.ReleasePath = defaultConfig.ReleasePath
	}

	if linuxConfig.EventMetadataExtractor == nil {
		linuxConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}

	return linuxConfig
}
