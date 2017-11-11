package iptablesctrl

import (
	"fmt"
	"os/exec"

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
func (i *Instance) createProxySets(vipipportset []string, pipipportset []string, portSetName string) error {
	destSetName, srcSetName := i.getSetNamePair(portSetName)

	ips, err := i.ipset.NewIpset(destSetName, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", destSetName, err)
	}

	i.vipTargetSet = ips

	for _, net := range vipipportset {
		if err = i.vipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}

	ips, err = i.ipset.NewIpset(srcSetName, "hash:ip,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", srcSetName, err)
	}

	i.pipTargetSet = ips

	for _, net := range pipipportset {
		zap.L().Error("Adding Net", zap.String("IPPORT", net))
		if err := i.pipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add pip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}

	return nil
}

func (i *Instance) updateProxySet(vipipportset []string, pipipportset []string, portSetName string) error {
	dstSetName, srcSetName := i.getSetNamePair(portSetName)
	vipTargetSet := ipset.IPSet{
		Name: dstSetName,
	}
	vipTargetSet.Flush()
	for _, net := range vipipportset {
		if err := i.vipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}
	pipTargetSet := ipset.IPSet{
		Name: srcSetName,
	}
	pipTargetSet.Flush()
	for _, net := range pipipportset {
		if err := i.pipTargetSet.Add(net, 0); err != nil {
			zap.L().Error("Failed to add vip", zap.Error(err))
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
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
		zap.L().Error("Error Creating Set", zap.String("Ipset Output", string(out)))
	}
	return err

}
