package monitor

import (
	"fmt"
	"strings"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/instance/uid"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/rpc"
	"github.com/aporeto-inc/trireme-lib/internal/monitor/rpc/registerer"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
	"go.uber.org/zap"
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
	Common    processor.Config
	MergeTags []string
	Monitors  map[Type]interface{}
}

func (c *Config) String() string {
	buf := fmt.Sprintf("MergeTags:[%s] ", strings.Join(c.MergeTags, ","))
	buf += fmt.Sprintf("Common:%+v ", c.Common)
	buf += fmt.Sprintf("Monitors:{")
	for k, v := range c.Monitors {
		buf += fmt.Sprintf("{%d:%+v},", k, v)
	}
	buf += fmt.Sprintf("}")
	return buf
}

type monitors struct {
	config          *Config
	monitors        map[Type]monitorinstance.Implementation
	userRPCListener rpcmonitor.Listener
	userRegisterer  registerer.Registerer
	rootRPCListener rpcmonitor.Listener
	rootRegisterer  registerer.Registerer
	syncHandler     processor.SynchronizationHandler
}

// NewMonitors instantiates all/any combination of monitors supported.
func NewMonitors(collector collector.EventCollector, puhandler processor.ProcessingUnitsHandler, c *Config) (Monitor, error) {

	var err error

	c.Common.Collector = collector
	c.Common.PUHandler = puhandler

	if err = c.Common.IsComplete(); err != nil {
		return nil, err
	}

	m := &monitors{
		config:      c,
		monitors:    make(map[Type]monitorinstance.Implementation),
		syncHandler: c.Common.SyncHandler,
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
			mon := cnimonitor.New()
			mon.SetupHandlers(&c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("CNI: %s", err.Error())
			}
			m.monitors[CNI] = mon

		case Docker:
			mon := dockermonitor.New()
			mon.SetupHandlers(&c.Common)
			if err := mon.SetupConfig(nil, v); err != nil {
				return nil, fmt.Errorf("Docker: %s", err.Error())
			}
			m.monitors[Docker] = mon

		case LinuxProcess:
			mon := linuxmonitor.New()
			mon.SetupHandlers(&c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("Process: %s", err.Error())
			}
			m.monitors[LinuxProcess] = mon

		case LinuxHost:
			mon := linuxmonitor.New()
			mon.SetupHandlers(&c.Common)
			if err := mon.SetupConfig(m.rootRegisterer, v); err != nil {
				return nil, fmt.Errorf("Host: %s", err.Error())
			}
			m.monitors[LinuxHost] = mon

		case UID:
			mon := uidmonitor.New()
			mon.SetupHandlers(&c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("UID: %s", err.Error())
			}
			m.monitors[UID] = mon

		default:
			return nil, fmt.Errorf("Unsupported type %d", k)
		}
	}

	zap.L().Debug("Monitor configuration", zap.String("conf", m.config.String()))

	return m, nil
}

func (m *monitors) Start() (err error) {

	if err = m.userRPCListener.Start(); err != nil {
		return err
	}

	if err = m.rootRPCListener.Start(); err != nil {
		return err
	}

	for _, v := range m.monitors {
		if err = v.Start(); err != nil {
			return err
		}
	}

	if m.syncHandler != nil {
		m.syncHandler.HandleSynchronizationComplete(processor.SynchronizationTypeInitial)
	}

	return nil
}

func (m *monitors) Stop() error {

	for _, v := range m.monitors {
		if err := v.Stop(); err != nil {
			return err
		}
	}

	if err := m.userRPCListener.Stop(); err != nil {
		return err
	}

	if err := m.rootRPCListener.Stop(); err != nil {
		return err
	}

	return nil
}
