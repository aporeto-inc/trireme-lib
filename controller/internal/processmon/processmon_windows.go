// +build windows

// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/policy"
)

type remoteMonitor struct {
}

// New is a method to create a new remote process monitor.
func New(ctx context.Context, p *env.RemoteParameters, c chan *policy.RuntimeError, r rpcwrapper.RPCClient) ProcessManager {
	return &remoteMonitor{}
}

// LaunchRemoteEnforcer for Windows: does nothing right now
func (p *remoteMonitor) LaunchRemoteEnforcer(
	contextID string,
	refPid int,
	refNSPath string,
	arg string,
	statsServerSecret string,
	procMountPoint string,
	enforcerType policy.EnforcerType,
) (bool, error) {
	return true, nil
}

// KillRemoteEnforcer for Windows: does nothing right now
func (p *remoteMonitor) KillRemoteEnforcer(contextID string, force bool) error {
	return nil
}
