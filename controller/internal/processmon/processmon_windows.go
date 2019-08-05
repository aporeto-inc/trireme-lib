// +build windows

// Package processmon is to manage and monitor remote enforcers.
package processmon

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/policy"
)

// RemoteMonitor is an instance of processMonitor
type RemoteMonitor struct {
}

// New is a method to create a new remote process monitor.
func New(ctx context.Context, p *env.RemoteParameters, c chan *policy.RuntimeError, r rpcwrapper.RPCClient) ProcessManager {
	return &RemoteMonitor{}
}

// LaunchRemoteEnforcer prepares the environment and launches the process. If the process
// is already launched, it will notify the caller, so that it can avoid any
// new initialization.
func (p *RemoteMonitor) LaunchRemoteEnforcer(
	contextID string,
	refPid int,
	refNSPath string,
	arg string,
	statsServerSecret string,
	procMountPoint string,
) (bool, error) {
	return false, nil
}

// KillRemoteEnforcer sends a rpc to the process to exit failing which it will kill the process
func (p *RemoteMonitor) KillRemoteEnforcer(contextID string, force bool) error {
	return nil
}
