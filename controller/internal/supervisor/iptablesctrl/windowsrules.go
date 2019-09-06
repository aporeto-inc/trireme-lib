// +build windows

package iptablesctrl

import (
	"context"
	"net"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
)

type IPImpl interface {
	provider.IptablesProvider
	GetIPSetPrefix() string
	GetIPSetParam() *ipset.Params
	ProtocolAllowed(proto string) bool
	IPFilter() func(net.IP) bool
	GetDefaultIP() string
	NeedICMP() bool
}

type iptables struct {
	impl                  IPImpl
	fqc                   *fqconfig.FilterQueue
	mode                  constants.ModeType
	ipset                 provider.IpsetProvider
	targetTCPSet          provider.Ipset
	cfg                   *runtime.Configuration
	contextIDToPortSetMap cache.DataStore
	serviceIDToIPsets     map[string]*ipsetInfo
	puToServiceIDs        map[string][]string
}

func createIPInstance(impl IPImpl, ips provider.IpsetProvider, fqc *fqconfig.FilterQueue, mode constants.ModeType) *iptables {
	return &iptables{
		impl: impl,
	}
}

// ConfigureRules configures the rules in the ACLs and datapath
func (w *iptables) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {

	return nil
}

// UpdateRules updates the rules with a new version
func (w *iptables) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	return nil
}

// DeleteRules
func (w *iptables) DeleteRules(version int, context string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string, puType common.PUType) error {
	return nil

}

// SetTargetNetworks sets the target networks of the supervisor
func (w *iptables) SetTargetNetworks(cfg *runtime.Configuration) error {
	return nil

}

// Start initializes any defaults
func (w *iptables) Run(ctx context.Context) error {
	return nil

}

// CleanUp requests the implementor to clean up all ACLs
func (w *iptables) CleanUp() error {
	return nil

}

// ACLProvider returns the ACL provider used by the implementor
func (w *iptables) ACLProvider() []provider.IptablesProvider {
	return nil

}
