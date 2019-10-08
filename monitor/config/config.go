package config

import (
	"fmt"
	"strings"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/policy"
)

// Type specifies the type of monitors supported.
type Type int

// Types supported.
const (
	CNI Type = iota + 1
	Docker
	LinuxProcess
	LinuxHost
	UID
	Kubernetes
	SSH
	Pod
)

// MonitorConfig specifies the configs for monitors.
type MonitorConfig struct {
	Common    *ProcessorConfig
	MergeTags []string
	Monitors  map[Type]interface{}
}

// String returns the configuration in string
func (c *MonitorConfig) String() string {
	buf := fmt.Sprintf("MergeTags:[%s] ", strings.Join(c.MergeTags, ","))
	buf += fmt.Sprintf("Common:%+v ", c.Common)
	buf += fmt.Sprintf("Monitors:{")
	for k, v := range c.Monitors {
		buf += fmt.Sprintf("{%d:%+v},", k, v)
	}
	buf += fmt.Sprintf("}")
	return buf
}

// ProcessorConfig holds configuration for the processors
type ProcessorConfig struct {
	Collector collector.EventCollector
	Policy    policy.Resolver
	MergeTags []string
}

// IsComplete checks if configuration is complete
func (c *ProcessorConfig) IsComplete() error {

	if c.Collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if c.Policy == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}
