package monitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/monitor/instance"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/cni"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/docker"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/linux"
	"github.com/aporeto-inc/trireme-lib/monitor/instance/uid"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
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
	Common    *processor.Config
	Monitors  map[Type]interface{}
	MergeTags []string
}

type monitors struct {
	config          *Config
	monitors        map[Type]monitorinstance.Implementation
	userRPCListener rpcmonitor.Listener
	userRegisterer  processor.Registerer
	rootRPCListener rpcmonitor.Listener
	rootRegisterer  processor.Registerer
	syncHandler     processor.SynchronizationHandler
}

// GetDefaultMonitors can be used as an example on how to setup configuration or
// use a set of defaults that work.
func GetDefaultMonitors(linuxProcess, linuxHost, uid, docker, cni bool) map[Type]interface{} {

	monitorsToEnable := make(map[Type]interface{})

	if cni {
		zap.L().Fatal("CNI not supported yet")
	}

	if linuxProcess {
		monitorsToEnable[LinuxProcess] = linuxmonitor.DefaultConfig(false)
	}

	if linuxHost {
		monitorsToEnable[LinuxHost] = linuxmonitor.DefaultConfig(true)
	}

	if uid {
		monitorsToEnable[UID] = uidmonitor.DefaultConfig()
	}

	if docker {
		monitorsToEnable[Docker] = dockermonitor.DefaultConfig()
	}

	return monitorsToEnable
}

func SetupConfig(
	linuxProcessEnable bool,
	linuxProcess *linuxmonitor.Config,
	linuxHostEnable bool,
	linuxHost *linuxmonitor.Config,
	uidEnable bool,
	uid *uidmonitor.Config,
	dockerEnable bool,
	docker *dockermonitor.Config,
	cniEnable bool,
	cni *cnimonitor.Config,
	common *processor.Config,
) *Config {

	// Configure Monitors
	monitorsToEnable := GetDefaultMonitors(
		linuxProcessEnable,
		linuxHostEnable,
		uidEnable,
		dockerEnable,
		cniEnable,
	)

	if linuxProcess != nil {
		monitorsToEnable[LinuxProcess] = linuxProcess
	}

	if linuxHost != nil {
		monitorsToEnable[LinuxHost] = linuxHost
	}

	if uid != nil {
		monitorsToEnable[UID] = uid
	}

	if docker != nil {
		monitorsToEnable[Docker] = docker
	}

	return &Config{
		Monitors: monitorsToEnable,
		Common:   common,
	}
}

// New instantiates all/any combination of monitors supported.
func New(c *Config) (Monitor, error) {

	var err error

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
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("CNI: %s", err.Error())
			}
			m.monitors[CNI] = mon

		case Docker:
			mon := dockermonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(nil, v); err != nil {
				return nil, fmt.Errorf("Docker: %s", err.Error())
			}
			m.monitors[Docker] = mon

		case LinuxProcess:
			mon := linuxmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("Process: %s", err.Error())
			}
			m.monitors[LinuxProcess] = mon

		case LinuxHost:
			mon := linuxmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.rootRegisterer, v); err != nil {
				return nil, fmt.Errorf("Host: %s", err.Error())
			}
			m.monitors[LinuxHost] = mon

		case UID:
			mon := uidmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.userRegisterer, v); err != nil {
				return nil, fmt.Errorf("UID: %s", err.Error())
			}
			m.monitors[UID] = mon

		default:
			return nil, fmt.Errorf("Unsupported type %d", k)
		}
	}

	return m, nil
}

func (m *monitors) Start() (err error) {

	m.userRPCListener.Start()

	m.rootRPCListener.Start()

	for _, v := range m.monitors {
		if err = v.Start(); err != nil {
			return err
		}
	}

	m.syncHandler.HandleSynchronizationComplete(processor.SynchronizationTypeInitial)

	return nil
}

func (m *monitors) Stop() error {

	for _, v := range m.monitors {
		if err := v.Stop(); err != nil {
			return err
		}
	}

	m.rootRPCListener.Stop()

	m.userRPCListener.Stop()

	return nil
}
