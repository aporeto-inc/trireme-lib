package linuxmonitor

import (
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/extractors"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
	StoredPath             string
	ReleasePath            string
	Host                   bool
	SSH                    bool
}

// DefaultConfig provides a default configuration
func DefaultConfig(host bool, ssh bool) *Config {

	return &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
		ReleasePath:            "/var/lib/aporeto/cleaner",
		StoredPath:             common.TriremeCgroupPath,
		Host:                   host,
		SSH:                    ssh,
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(linuxConfig *Config) *Config {

	defaultConfig := DefaultConfig(linuxConfig.Host, linuxConfig.SSH)

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
