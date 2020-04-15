package iptablesctrl

import (
	"fmt"
	"strconv"

	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

// updateTargetNetworks updates the set of target networks. Tries to minimize
// read/writes to the ipset structures
func (i *iptables) updateTargetNetworks(set provider.Ipset, old, new []string) error {

	// We need to delete first, because of nomatch.
	// For example, if old has 1.2.3.4 and new has !1.2.3.4, then we delete the 1.2.3.4 first
	// before we can add the 1.2.3.4 with the nomatch option.

	deleteMap := map[string]bool{}
	addMap := map[string]bool{}
	for _, net := range old {
		deleteMap[net] = true
	}
	for _, net := range new {
		if _, ok := deleteMap[net]; ok {
			deleteMap[net] = false
			continue
		}
		addMap[net] = true
	}

	for net, delete := range deleteMap {
		if delete {
			if err := i.aclmanager.DelFromIPset(set, net); err != nil {
				zap.L().Debug("unable to remove network from set", zap.Error(err))
			}
		}
	}

	for net, add := range addMap {
		if add {
			if err := i.aclmanager.AddToIPset(set, net); err != nil {
				return fmt.Errorf("unable to update target set: %s", err)
			}
		}
	}

	return nil
}

// createProxySet creates a new target set -- ipportset is a list of {ip,port}
func (i *iptables) createProxySets(portSetName string) error {
	destSetName, srvSetName := i.getSetNames(portSetName)

	_, err := i.ipset.NewIpset(destSetName, "hash:net,port", i.impl.GetIPSetParam())
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", destSetName, err)
	}

	// create ipset for port match
	_, err = i.ipset.NewIpset(srvSetName, proxySetPortIpsetType, nil)
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", srvSetName, err)
	}

	return nil
}

func (i *iptables) updateProxySet(policy *policy.PUPolicy, portSetName string) error {

	ipFilter := i.impl.IPFilter()
	dstSetName, srvSetName := i.getSetNames(portSetName)
	vipTargetSet := i.ipset.GetIpset(dstSetName)
	if ferr := vipTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the vip proxy set")
	}

	for _, dependentService := range policy.DependentServices() {
		addresses := dependentService.NetworkInfo.Addresses
		min, max := dependentService.NetworkInfo.Ports.Range()
		for _, addr := range addresses {
			if ipFilter(addr.IP) {
				for i := int(min); i <= int(max); i++ {
					pair := addr.String() + "," + strconv.Itoa(i)
					if err := vipTargetSet.Add(pair, 0); err != nil {
						return fmt.Errorf("unable to add dependent ip %s to target networks ipset: %s", pair, err)
					}
				}
			}
		}
	}

	srvTargetSet := i.ipset.GetIpset(srvSetName)
	if ferr := srvTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the pip proxy set")
	}

	for _, exposedService := range policy.ExposedServices() {
		min, max := exposedService.PrivateNetworkInfo.Ports.Range()
		for i := int(min); i <= int(max); i++ {
			if err := srvTargetSet.Add(strconv.Itoa(i), 0); err != nil {
				zap.L().Error("Failed to add vip", zap.Error(err))
				return fmt.Errorf("unable to add ip %d to target ports ipset: %s", i, err)
			}
		}
		if exposedService.PublicNetworkInfo != nil {
			min, max := exposedService.PublicNetworkInfo.Ports.Range()
			for i := int(min); i <= int(max); i++ {
				if err := srvTargetSet.Add(strconv.Itoa(i), 0); err != nil {
					zap.L().Error("Failed to VIP for public network", zap.Error(err))
					return fmt.Errorf("Failed to program VIP: %s", err)
				}
			}
		}
	}
	return nil
}

//getSetNamePair returns a pair of strings represent proxySetNames
func (i *iptables) getSetNames(portSetName string) (string, string) {
	return portSetName + "-dst", portSetName + "-srv"
}
