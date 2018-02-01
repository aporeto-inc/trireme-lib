package monitor

import (
	"context"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/monitor/config"
	monitorinstance "github.com/aporeto-inc/trireme-lib/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/uid"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/policy"
	"go.uber.org/zap"
)

type monitors struct {
	config          *config.MonitorConfig
	monitors        map[config.Type]monitorinstance.Implementation
	userRPCListener rpcmonitor.Listener
	userRegisterer  registerer.Registerer
	rootRPCListener rpcmonitor.Listener
	rootRegisterer  registerer.Registerer
	policy          policy.Resolver
}

// NewMonitors instantiates all/any combination of monitors supported.
func NewMonitors(opts ...Options) (Monitor, error) {

	var err error

	c := &config.MonitorConfig{
		MergeTags: []string{},
		Common:    &config.ProcessorConfig{},
		Monitors:  map[config.Type]interface{}{},
	}

	for _, opt := range opts {
		opt(c)
	}

	if err = c.Common.IsComplete(); err != nil {
		return nil, err
	}

	m := &monitors{
		config:   c,
		monitors: make(map[config.Type]monitorinstance.Implementation),
	}

	if m.userRPCListener, m.userRegisterer, err = rpcmonitor.New(
		rpcmonitor.DefaultRPCAddress,
		false,
	); err != nil {
		return nil, fmt.Errorf("Unable to create user RPC Listener %s", err.Error())
	}

	if m.rootRPCListener, m.rootRegisterer, err = rpcmonitor.New(
		rpcmonitor.DefaultRootRPCAddress,
		true,
	); err != nil {
		return nil, fmt.Errorf("Unable to create user RPC Listener %s", err.Error())
	}

	for k, v := range c.Monitors {
		switch k {
		case config.CNI:
			mon := cnimonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("CNI: %s", err.Error())
			}
			m.monitors[config.CNI] = mon

		case config.Docker:
			mon := dockermonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(nil, v); err != nil {
				return nil, fmt.Errorf("Docker: %s", err.Error())
			}
			m.monitors[config.Docker] = mon

		case config.LinuxProcess:
			mon := linuxmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("Process: %s", err.Error())
			}
			m.monitors[config.LinuxProcess] = mon

		case config.LinuxHost:
			mon := linuxmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.rootRegisterer, v); err != nil {
				return nil, fmt.Errorf("Host: %s", err.Error())
			}
			m.monitors[config.LinuxHost] = mon

		case config.UID:
			mon := uidmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("UID: %s", err.Error())
			}
			m.monitors[config.UID] = mon

		default:
			return nil, fmt.Errorf("Unsupported type %d", k)
		}
	}

	zap.L().Debug("Monitor configuration", zap.String("conf", m.config.String()))

	return m, nil
}

func (m *monitors) Run(ctx context.Context) (err error) {

	if err = m.userRPCListener.Run(ctx); err != nil {
		return err
	}

	if err = m.rootRPCListener.Run(ctx); err != nil {
		return err
	}

	for _, v := range m.monitors {
		if err = v.Run(ctx); err != nil {
			return err
		}
	}

	if m.policy != nil {
		m.policy.HandleSynchronizationComplete(policy.SynchronizationTypeInitial)
	}

	return nil
}

// UpdateConfiguration updates the configuration of the monitors.
func (m *monitors) UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error {
	// Monitor configuration cannot change at this time.
	// TODO:
	return nil
}

// Resync resyncs the monitor
func (m *monitors) Resync(ctx context.Context) error {

	failure := false
	var errs string

	for _, i := range m.monitors {
		if err := i.ReSync(ctx); err != nil {
			errs = errs + err.Error()
			failure = true
		}
	}

	if failure {
		return fmt.Errorf("Monitor resync failed: %s", errs)
	}

	return nil
}
