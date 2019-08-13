// +build windows

package iptablesctrl

import (
	"context"

	"go.aporeto.io/trireme-lib/common"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

type rules struct {
	provider           provder.IpsetProvider
	excludedNetworkSet provider.IpsetProvider
}

// ConfigureRules configures the rules in the ACLs and datapath
func (r *rules) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	return nil
}

// UpdateRules updates the rules with a new version
func (r *rules) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	return nil
}

// DeleteRules
func (r *rules) DeleteRules(version int, context string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, puType common.PUType) error {
	return nil

}

// SetTargetNetworks sets the target networks of the supervisor
func (r *rules) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil

}

// Start initializes any defaults
func (r *rules) Run(ctx context.Context) error {
	return nil

}

// CleanUp requests the implementor to clean up all ACLs
func (r *rules) CleanUp() error {
	return nil

}

// ACLProvider returns the ACL provider used by the implementor
func (r *rules) ACLProvider() []provider.IptablesProvider {
	return nil

}
