package iptablesctrl

import (
	"fmt"
	"net"

	"github.com/aporeto-inc/go-ipset/ipset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/runtime"
)

const (
	ipv6 = "ipv6"
)

var ipsetV6Param *ipset.Params

func init() {
	ipsetV6Param = &ipset.Params{HashFamily: "inet6"}
}

func filterIPv6(c *runtime.Configuration) {
	filter := func(ips []string) {
		var filteredIPs []string

		for _, ip := range ips {
			netIP, _, _ := net.ParseCIDR(ip)
			if netIP.To4() == nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	return &runtime.Configuration{
		TCPTargetNetworks: filter(c.TCPTargetNetworks),
		UDPTargetNetworks: filter(c.UDPTargetNetworks),
		ExcludedNetworks:  filter(c.ExcludedNetworks),
	}
}

//Setup
func (i *Instance) setupIPv6() {
	iptV6, err := provider.NewGoIPTablesProviderV6([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	// Create all the basic target sets. These are the global target sets
	// that do not depend on policy configuration. If they already exist
	// we will delete them and start again.
	ips := provider.NewGoIPsetProvider()

	targetTCPSet, targetUDPSet, excludedSet, err := createGlobalSets(i.iptInstance.ipset)
	if err != nil {
		return fmt.Errorf("unable to create global sets: %s", err)
	}

	i.iptInstance.targetTCPSet = targetTCPSet
	i.iptInstance.targetUDPSet = targetUDPSet
	i.iptInstance.excludedNetworksSet = excludedSet

	if err := i.updateAllTargetNetworks(i.iptInstance.cfg, &runtime.Configuration{}); err != nil {
		// If there is a failure try to clean up on exit.
		i.iptInstance.ipset.DestroyAll(chainPrefix) // nolint errcheck
		return fmt.Errorf("unable to initialize target networks: %s", err)
	}

}

// SetTargetNetworks updates ths target networks. There are three different
// types of target networks:
//   - TCPTargetNetworks for TCP traffic (by default 0.0.0.0/0)
//   - UDPTargetNetworks for UDP traffic (by default empty)
//   - ExcludedNetworks that are always ignored (by default empty)
func (i *Instance) SetTargetNetworks(c *runtime.Configuration) error {

	if c == nil {
		return nil
	}

	cfg := filterIPv6(c)

	var oldConfig *runtime.Configuration
	if i.iptInstance.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.iptInstance.cfg.DeepCopy()
	}

	// If there are no target networks, capture all traffic
	if len(cfg.TCPTargetNetworks) == 0 {
		cfg.TCPTargetNetworks = []string{"::/1", "8000::/1"}
	}

	if err := i.updateAllTargetNetworks(cfg, oldConfig); err != nil {
		return err
	}

	i.iptInstance.cfg = cfg

	return nil
}
