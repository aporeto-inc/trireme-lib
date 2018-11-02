package iptablesctrl

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/bvandewalle/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/policy"
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

	// _, err := i.ipset.NewIpset(targetNetworkSet, "hash:ip", &ipset.Params{})
	// if err != nil {
	// 	return fmt.Errorf("unable to create ipset for %s: %s", targetNetworkSet, err)
	// }
	path, err := exec.LookPath("ipset")

	if err != nil {
		return fmt.Errorf("Error not found ipset %s", err)
	}
	if out, err := exec.Command(path, "--create", targetNetworkSet, "nethash").CombinedOutput(); err != nil {
		return fmt.Errorf("Unable to create targetnetset %s %s %s", targetNetworkSet, err, out)
	}
	// i.targetSet = ips

	// for _, net := range networks {
	// 	if err := i.targetSet.Add(net, 0); err != nil {
	// 		return fmt.Errorf("createTargetSet: unable to add ip %s to target networks ipset: %s", net, err)
	// 	}
	// }

	return nil
}

// createProxySet creates a new target set -- ipportset is a list of {ip,port}
func (i *Instance) createProxySets(portSetName string) error {
	destSetName, srcSetName, srvSetName := i.getSetNames(portSetName)

	path, err := exec.LookPath("ipset")

	if err != nil {
		return fmt.Errorf("Error not found ipset %s", err)
	}
	if out, err := exec.Command(path, "--create", destSetName, "ipporthash", "--network", "10.1.0.0/16").CombinedOutput(); err != nil {
		return fmt.Errorf("Unable to create proxy %s %s %s", destSetName, err, out)
	}

	if out, err := exec.Command(path, "--create", srcSetName, "ipporthash", "--network", "10.1.0.0/16").CombinedOutput(); err != nil {
		return fmt.Errorf("Unable to create srcSet %s %s %s", srcSetName, err, out)
	}
	// _, err := i.ipset.NewIpset(destSetName, "hash:ip,port", &ipset.Params{})
	// if err != nil {
	// 	return fmt.Errorf("unable to create ipset for %s: %s", destSetName, err)
	// }

	// _, err = i.ipset.NewIpset(srcSetName, "hash:ip,port", &ipset.Params{})
	// if err != nil {
	// 	return fmt.Errorf("unable to create ipset for %s: %s", srcSetName, err)
	// }

	err = i.createPUPortSet(srvSetName)
	// _, err = i.ipset.NewIpset(srvSetName, "bitmap:port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", srvSetName, err)
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

func (i *Instance) updateProxySet(policy *policy.PUPolicy, portSetName string) error {

	dstSetName, srcSetName, srvSetName := i.getSetNames(portSetName)
	vipTargetSet := ipset.IPSet{
		Name: dstSetName,
	}
	if ferr := vipTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the vip proxy set")
	}

	for _, dependentService := range policy.DependentServices() {
		addresses := dependentService.NetworkInfo.Addresses
		min, max := dependentService.NetworkInfo.Ports.Range()
		for _, addr := range addresses {
			for i := int(min); i <= int(max); i++ {
				pair := addr.IP.To4().String() + "," + strconv.Itoa(i)
				if err := vipTargetSet.Add(pair, 0); err != nil {
					return fmt.Errorf("unable to add dependent ip %s to target networks ipset: %s", pair, err)
				}
			}
		}
	}

	pipTargetSet := ipset.IPSet{
		Name: srcSetName,
	}
	if ferr := pipTargetSet.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the pip proxy set")
	}

	srvTargetSet := ipset.IPSet{
		Name: srvSetName,
	}
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
	}
	return nil
}

//getSetNamePair returns a pair of strings represent proxySetNames
func (i *Instance) getSetNames(portSetName string) (string, string, string) {
	return "dst-" + portSetName, "src-" + portSetName, "srv-" + portSetName

}

//Not using ipset from coreos library they don't support bitmap:port
func (i *Instance) createPUPortSet(setname string) error {
	//Bitmap type is not supported by the ipset library
	//_, err := i.ipset.NewIpset(setname, "hash:port", &ipset.Params{})
	path, _ := exec.LookPath("ipset")
	out, err := exec.Command(path, "--create", setname, "portmap", "--from", "0", "--to", "65535").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "set with the same name already exists") {
			zap.L().Warn("Set already exists - cleaning up", zap.String("set name", setname))
			// Clean up the existing set
			if _, cerr := exec.Command(path, "-F", setname).CombinedOutput(); cerr != nil {
				return fmt.Errorf("Failed to clean up existing ipset: %s", err)
			}
			return nil
		}
		zap.L().Error("Unable to create set", zap.String("set name", setname), zap.String("ipset-output", string(out)))
	}
	return err

}

func (i *Instance) destroyAllIPsets() error {
	path, _ := exec.LookPath("ipset")
	out, err := exec.Command(path, "-L").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error listing ipsets %s %s", err, out)
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(out))
	for scanner.Scan() {
		if strings.HasPrefix(strings.TrimSuffix(scanner.Text(), "\n"), "Name:") {
			output := strings.Split(strings.TrimSuffix(scanner.Text(), "\n"), ":")
			if len(output) < 2 {
				continue
			}
			if out, err := exec.Command(path, "-X", strings.Trim(output[1], " ")).CombinedOutput(); err != nil {
				return fmt.Errorf("Error destroying ipsets %s %s", err, out)
			}

		}
	}
	return nil
}
