// +build windows

package iptablesctrl

import (
	"context"
	"net"

	"go.aporeto.io/trireme-lib/common"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

type rules struct {
	provider           provider.IpsetProvider
	excludedNetworkSet provider.IpsetProvider
	cfg                *runtime.Configuration
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

type ipFilter func(net.IP) bool

func filterNetworks(c *runtime.Configuration, filter ipFilter) *runtime.Configuration {
	filterIPs := func(ips []string) []string {
		var filteredIPs []string

		for _, ip := range ips {
			netIP := net.ParseIP(ip)
			if netIP == nil {
				netIP, _, _ = net.ParseCIDR(ip)
			}

			if filter(netIP) {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	return &runtime.Configuration{
		TCPTargetNetworks: filterIPs(c.TCPTargetNetworks),
		UDPTargetNetworks: filterIPs(c.UDPTargetNetworks),
		ExcludedNetworks:  filterIPs(c.ExcludedNetworks),
	}
}

// SetTargetNetworks sets the target networks of the supervisor
func (r *rules) SetTargetNetworks(cfg *runtime.Configuration) error {
	if cfg == nil {
		return nil
	}

	c := filterNetworks(cfg, r.impl.IPFilter())
	var oldConfig *runtime.Configuration

	if r.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.cfg.DeepCopy()
	}

	if err := r.updateAllTargetNetworks(c, oldConfig); err != nil {
		return err
	}

	r.cfg = c
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
