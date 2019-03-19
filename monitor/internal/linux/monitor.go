package linuxmonitor

import (
	"context"
	"fmt"
	"regexp"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
)

// LinuxMonitor captures all the monitor processor information
// It implements the EventProcessor interface of the rpc monitor
type LinuxMonitor struct {
	proc *linuxProcessor
}

// New returns a new implmentation of a monitor implmentation
func New() *LinuxMonitor {

	return &LinuxMonitor{
		proc: &linuxProcessor{},
	}
}

// Run implements Implementation interface
func (l *LinuxMonitor) Run(ctx context.Context) error {

	if err := l.proc.config.IsComplete(); err != nil {
		return fmt.Errorf("linux %t: %s", l.proc.host, err)
	}

	return l.Resync(ctx)
}

// SetupConfig provides a configuration to implmentations. Every implmentation
// can have its own config type.
func (l *LinuxMonitor) SetupConfig(registerer registerer.Registerer, cfg interface{}) error {

	if cfg == nil {
		cfg = DefaultConfig(false, false)
	}

	linuxConfig, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("Invalid configuration specified")
	}

	if registerer != nil {
		if linuxConfig.SSH {
			if err := registerer.RegisterProcessor(common.SSHSessionPU, l.proc); err != nil {
				return err
			}
		} else {
			if err := registerer.RegisterProcessor(common.HostNetworkPU, l.proc); err != nil {
				return err
			}
			if err := registerer.RegisterProcessor(common.HostPU, l.proc); err != nil {
				return err
			}
			if err := registerer.RegisterProcessor(common.LinuxProcessPU, l.proc); err != nil {
				return err
			}
		}
	}

	// Setup defaults
	linuxConfig = SetupDefaultConfig(linuxConfig)

	// Setup config
	l.proc.host = linuxConfig.Host
	l.proc.ssh = linuxConfig.SSH
	l.proc.netcls = cgnetcls.NewCgroupNetController(common.TriremeCgroupPath, linuxConfig.ReleasePath)

	l.proc.regStart = regexp.MustCompile("^[a-zA-Z0-9_]{1,11}$")
	l.proc.regStop = regexp.MustCompile("^/trireme/[a-zA-Z0-9_]{1,11}$")

	l.proc.metadataExtractor = linuxConfig.EventMetadataExtractor
	if l.proc.metadataExtractor == nil {
		return fmt.Errorf("Unable to setup a metadata extractor")
	}

	return nil
}

// SetupHandlers sets up handlers for monitors to invoke for various events such as
// processing unit events and synchronization events. This will be called before Start()
// by the consumer of the monitor
func (l *LinuxMonitor) SetupHandlers(m *config.ProcessorConfig) {

	l.proc.config = m
}

// Resync instructs the monitor to do a resync.
func (l *LinuxMonitor) Resync(ctx context.Context) error {
	return l.proc.Resync(ctx, nil)
}
