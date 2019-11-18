// +build windows

package monitor

import (
	"context"
	"fmt"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	windowsmonitor "go.aporeto.io/trireme-lib/monitor/internal/windows"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.aporeto.io/trireme-lib/monitor/remoteapi/server"
	"go.uber.org/zap"
)

type monitors struct {
	config     *config.MonitorConfig
	monitors   map[config.Type]Implementation
	registerer registerer.Registerer
	server     server.APIServer
}

// Run starts the monitor.
func (m *monitors) Run(ctx context.Context) (err error) {
	if err = m.server.Run(ctx); err != nil {
		return err
	}

	for _, v := range m.monitors {
		if err = v.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

// UpdateConfiguration updates the configuration of the monitor
func (m *monitors) UpdateConfiguration(ctx context.Context, config *config.MonitorConfig) error {
	return nil
}

// Resync requests to the monitor to do a resync.
func (m *monitors) Resync(ctx context.Context) error {

	failure := false
	var errs string

	for _, i := range m.monitors {
		if err := i.Resync(ctx); err != nil {
			errs = errs + err.Error()
			failure = true
		}
	}

	if failure {
		return fmt.Errorf("Monitor resync failed: %s", errs)
	}

	return nil
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
		monitors: make(map[config.Type]Implementation),
	}

	m.registerer = registerer.New()

	m.server, err = server.NewEventServer(common.TriremeSocket, m.registerer)
	if err != nil {
		return nil, err
	}

	for k, v := range c.Monitors {
		switch k {
		case config.Windows:
			mon := windowsmonitor.New()
			mon.SetupHandlers(c.Common)
			// TODO(windows): make a real Windows monitor option rather than using LinuxHost
			if err := mon.SetupConfig(m.registerer, v); err != nil {
				return nil, fmt.Errorf("Windows: %s", err.Error())
			}
			m.monitors[config.Windows] = mon
		case config.LinuxHost:
			mon := windowsmonitor.New()
			mon.SetupHandlers(c.Common)
			if err := mon.SetupConfig(m.registerer, v); err != nil {
				return nil, fmt.Errorf("Host: %s", err.Error())
			}
			m.monitors[config.LinuxHost] = mon
			/* default:
			return nil, nil //fmt.Errorf("Unsupported type %d", k) */
		}
	}
	zap.L().Debug("Monitor configuration", zap.String("conf", m.config.String()))

	return m, nil

}
