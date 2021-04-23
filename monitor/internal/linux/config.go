package linuxmonitor

import (
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
	StoredPath             string
	ReleasePath            string
	Host                   bool
}

// DefaultConfig provides a default configuration
func DefaultConfig(host bool) *Config {

	return &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
		ReleasePath:            "",
		StoredPath:             common.TriremeCgroupPath,
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

	if linuxConfig.StoredPath == "" {
		linuxConfig.StoredPath = common.TriremeCgroupPath
	}

	return linuxConfig
}
