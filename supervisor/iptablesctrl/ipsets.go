package iptablesctrl

import (
	"fmt"

	"github.com/bvandewalle/go-ipset/ipset"
	"go.uber.org/zap"
)

// updateTargetNetworks updates the set of target networks. Tries to minimize
// read/writes to the ipset structures
func (i *Instance) updateTargetNetworks(old, new []string) error {

	deleteMap := map[string]bool{}
	for _, net := range old {
		deleteMap[net] = true
	}

	for _, net := range new {
		if _, ok := deleteMap[net]; ok {
			deleteMap[net] = false
			continue
		}

		if err := i.targetSet.Add(net, 0); err != nil {
			return fmt.Errorf("Failed to update target set")
		}
	}

	for net, delete := range deleteMap {
		if delete {
			if err := i.targetSet.Del(net); err != nil {
				zap.L().Debug("Failed to remove network from set")
			}
		}
	}
	return nil
}

// createTargetSet creates a new target set
func (i *Instance) createTargetSet(networks []string) error {

	ips, err := i.ipset.NewIpset(targetNetworkSet, "hash:net", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", targetNetworkSet, err)
	}

	i.targetSet = ips

	for _, net := range networks {
		if err := i.targetSet.Add(net, 0); err != nil {
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}

	return nil
}

// createProxySet creates a new target set -- ipportset is a list of {ip,port}
func (i *Instance) createProxySets(vipipportset []string, pipipportset []string) error {

	ips, err := i.ipset.NewIpset(destProxyServiceSet, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", destProxyServiceSet, err)
	}

	i.vipTargetSet = ips

	for _, net := range vipipportset {
		if err := i.vipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}

	ips, err = i.ipset.NewIpset(srcProxyServiceSet, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", srcProxyServiceSet, err)
	}

	i.pipTargetSet = ips

	for _, net := range pipipportset {
		if err := i.pipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}

	return nil
}
