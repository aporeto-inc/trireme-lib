package iptablesctrl

import (
	"fmt"
	"strconv"

	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

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
