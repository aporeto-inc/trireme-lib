package iptablesctrl

import (
	"fmt"
	"os/exec"

	"github.com/aporeto-inc/trireme-lib/policy"
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
			return fmt.Errorf("unable to update target set: %s", err)
		}
	}

	for net, delete := range deleteMap {
		if delete {
			if err := i.targetSet.Del(net); err != nil {
				zap.L().Debug("unable to remove network from set", zap.Error(err))
			}
		}
	}
	return nil
}

// createTargetSet creates a new target set
func (i *Instance) createTargetSet(networks []string) error {

	ips, err := i.ipset.NewIpset(targetNetworkSet, "hash:net", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", targetNetworkSet, err)
	}

	i.targetSet = ips

	for _, net := range networks {
		if err := i.targetSet.Add(net, 0); err != nil {
			return fmt.Errorf("unable to add ip %s to target networks ipset: %s", net, err)
		}
	}

	return nil
}

// createProxySet creates a new target set -- ipportset is a list of {ip,port}
func (i *Instance) createProxySets(portSetName string) error {
	destSetName, srcSetName := i.getSetNamePair(portSetName)

	_, err := i.ipset.NewIpset(destSetName, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", destSetName, err)
	}

	_, err = i.ipset.NewIpset(srcSetName, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", srcSetName, err)
	}

	return nil
}

// createUIDSets creates the UID specific sets
func (i *Instance) createUIDSets(contextID string, puInfo *policy.PUInfo) error {
	if puInfo.Runtime.Options().UserID != "" {
		portSetName := puPortSetName(contextID, PuPortSet)

		if puseterr := i.createPUPortSet(portSetName); puseterr != nil {
			return puseterr
		}
	}
	return nil
}

func (i *Instance) updateProxySet(services *policy.ProxiedServicesInfo, portSetName string) error {

	dstSetName, srcSetName := i.getSetNamePair(portSetName)
	vipTargetSet := ipset.IPSet{
		Name: dstSetName,
	}
	if ferr := vipTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the vip proxy set")
	}

	for _, net := range services.PublicIPPortPair {
		if err := vipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("unable to add ip %s to target networks ipset: %s", net, err)
		}
	}

	pipTargetSet := ipset.IPSet{
		Name: srcSetName,
	}
	if ferr := pipTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the pip proxy set")
	}

	for _, net := range services.PrivateIPPortPair {
		if err := pipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("unable to add ip %s to target networks ipset: %s", net, err)
		}
	}
	return nil
}

//getSetNamePair returns a pair of strings represent proxySetNames
func (i *Instance) getSetNamePair(portSetName string) (string, string) {
	return "dst-" + portSetName, "src-" + portSetName

}

//Not using ipset from coreos library they don't support bitmap:port
func (i *Instance) createPUPortSet(setname string) error {
	//Bitmap type is not supported by the ipset library
	//_, err := i.ipset.NewIpset(setname, "hash:port", &ipset.Params{})
	path, _ := exec.LookPath("ipset")
	out, err := exec.Command(path, "create", setname, "bitmap:port", "range", "0-65535", "timeout", "0").CombinedOutput()
	if err != nil {
		zap.L().Error("Unable to creating set", zap.String("ipset-output", string(out)))
	}
	return err

}
