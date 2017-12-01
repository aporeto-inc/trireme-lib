package monitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/monitor/impl"
	"github.com/aporeto-inc/trireme-lib/monitor/impl/cni"
	"github.com/aporeto-inc/trireme-lib/monitor/impl/docker"
	"github.com/aporeto-inc/trireme-lib/monitor/impl/linux"
	"github.com/aporeto-inc/trireme-lib/monitor/impl/uid"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
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
)

// Config specifies the configs for monitors.
type Config struct {
	Collector   collector.EventCollector
	PUHandler   monitorimpl.ProcessingUnitsHandler
	SyncHandler monitorimpl.SynchronizationHandler
	Monitors    map[Type]interface{}
}

type monitors struct {
	config          *Config
	monitors        map[Type]monitorimpl.Implementation
	userRPCListener rpcmonitor.Listener
	userRegisterer  processor.Registerer
	rootRPCListener rpcmonitor.Listener
	rootRegisterer  processor.Registerer
}

// New instantiates all/any combination of monitors supported.
func New(c *Config) (Monitor, error) {

	var err error

	m := &monitors{
		config:   c,
		monitors: make(map[Type]monitorimpl.Implementation),
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
		case CNI:
			monitor := cnimonitor.New()
			monitor.SetupHandlers(c.Collector, c.PUHandler, c.SyncHandler)
			if err := monitor.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, err
			}
			m.monitors[CNI] = monitor

		case Docker:
			monitor := dockermonitor.New()
			monitor.SetupHandlers(c.Collector, c.PUHandler, c.SyncHandler)
			if err := monitor.SetupConfig(nil, v); err != nil {
				return nil, err
			}
			m.monitors[Docker] = monitor

		case LinuxProcess:
			m.monitors[LinuxProcess] = linuxmonitor.New()
			monitor.SetupHandlers(c.Collector, c.PUHandler, c.SyncHandler)
			if err := monitor.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, err
			}
			m.monitors[LinuxProcess] = monitor

		case LinuxHost:
			m.monitors[LinuxHost] = linuxmonitor.New()
			monitor.SetupHandlers(c.Collector, c.PUHandler, c.SyncHandler)
			if err := monitor.SetupConfig(m.rootRegisterer, v); err != nil {
				return nil, err
			}
			m.monitors[LinuxHost] = monitor

		case UID:
			m.monitors[UID] = uidmonitor.New()
			monitor.SetupHandlers(c.Collector, c.PUHandler, c.SyncHandler)
			if err := monitor.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, err
			}
			m.monitors[UID] = monitor

		default:
			return nil, fmt.Errorf("Unsupported type %d", k)
		}
	}

	return m, nil
}

func (m *monitors) Start() (err error) {

	for k, v := range m.monitors {
		if err = v.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (m *monitors) Stop() error {

	for k, v := range m.monitors {
		if err = v.Stop(); err != nil {
			return err
		}
	}

	return nil
}
