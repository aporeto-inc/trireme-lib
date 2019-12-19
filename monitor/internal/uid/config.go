package uidmonitor

import (
	"go.aporeto.io/trireme-lib/monitor/extractors"
)

// Config is the configuration options to start a CNI monitor
type Config struct {
	EventMetadataExtractor extractors.EventMetadataExtractor
	StoredPath             string
	ReleasePath            string
}

// DefaultConfig provides default configuration for uid monitor
func DefaultConfig() *Config {

	return &Config{
		EventMetadataExtractor: extractors.UIDMetadataExtractor,
		StoredPath:             "/var/run/trireme_uid",
		ReleasePath:            "",
	}
}

// SetupDefaultConfig adds defaults to a partial configuration
func SetupDefaultConfig(uidConfig *Config) *Config {

	defaultConfig := DefaultConfig()

	if uidConfig.ReleasePath == "" {
		uidConfig.ReleasePath = defaultConfig.ReleasePath
	}
	if uidConfig.StoredPath == "" {
		uidConfig.StoredPath = defaultConfig.StoredPath
	}
	if uidConfig.EventMetadataExtractor == nil {
		uidConfig.EventMetadataExtractor = defaultConfig.EventMetadataExtractor
	}

	return uidConfig
}
