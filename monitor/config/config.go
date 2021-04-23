package config

import (
	"fmt"
	"strings"
	"sync"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// Type specifies the type of monitors supported.
type Type int

// Types supported.
const (
	Docker Type = iota + 1
	LinuxProcess
	LinuxHost
	K8s
	Windows
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
	buf += fmt.Sprintf("Monitors:{") // nolint
	for k, v := range c.Monitors {
		buf += fmt.Sprintf("{%d:%+v},", k, v)
	}
	buf += fmt.Sprintf("}") // nolint:gosimple // lint:ignore S1039
	return buf
}

// ProcessorConfig holds configuration for the processors
type ProcessorConfig struct {
	Collector           collector.EventCollector
	Policy              policy.Resolver
	ExternalEventSender []external.ReceiverRegistration
	MergeTags           []string
	ResyncLock          *sync.RWMutex
}

// IsComplete checks if configuration is complete
func (c *ProcessorConfig) IsComplete() error {

	if c.Collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if c.Policy == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}
	if c.ResyncLock == nil {
		return fmt.Errorf("Missing resyncLock: puHandler")
	}
	// not all monitors implement external.ReceiveEvents
	// so ExternalEventSender is optional

	return nil
}
