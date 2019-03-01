package iptablesctrl

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

// updateTargetNetworks updates the set of target networks. Tries to minimize
// read/writes to the ipset structures
func (i *Instance) updateTargetNetworks(old, new []string) error {

	deleteMap := map[string]bool{}
	for _, cidr := range old {
		deleteMap[cidr] = true
	}

	for _, cidr := range new {
		if _, ok := deleteMap[cidr]; ok {
			deleteMap[cidr] = false
			continue
		}

		ip, _, _ := net.ParseCIDR(cidr) //nolint
		if ip.To4() != nil {
			if err := i.addToIPset(targetNetworkSetV4, cidr); err != nil {
				return fmt.Errorf("unable to update target set: %s", err)
			}
		} else {
			if err := i.addToIPset(targetNetworkSetV6, cidr); err != nil {
				return fmt.Errorf("unable to update target set: %s", err)
			}
		}
	}

	for cidr, delete := range deleteMap {
		if delete {
			ip, _, _ := net.ParseCIDR(cidr) //nolint

			if ip.To4() != nil {
				if err := i.delFromIPset(targetNetworkSetV4, cidr); err != nil {
					zap.L().Debug("unable to remove network from set", zap.Error(err))
				}
			} else {
				if err := i.delFromIPset(targetNetworkSetV6, cidr); err != nil {
					zap.L().Debug("unable to remove network from set", zap.Error(err))
				}
			}
		}
	}
	return nil
}

// createTargetSet creates a new target set
func (i *Instance) createTargetSet(networks []string) error {

	_, err := i.ipset.NewIpset(targetNetworkSetV4, "hash:net", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", targetNetworkSetV4, err)
	}

	_, err = i.ipset.NewIpset(targetNetworkSetV6, "hash:net", &ipset.Params{HashFamily: "inet6"})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", targetNetworkSetV6, err)
	}

	i.targetSet = true

	i.iptV4.SetTargetSet(targetNetworkSetV4)
	i.iptV6.SetTargetSet(targetNetworkSetV6)

	for _, cidr := range networks {
		ip, _, _ := net.ParseCIDR(cidr) //nolint
		if ip.To4() != nil {
			if err := i.addToIPset(targetNetworkSetV4, cidr); err != nil {
				return fmt.Errorf("createTargetSet: unable to add ip %s to target networks ipset: %s", cidr, err)
			}
		} else {
			if err := i.addToIPset(targetNetworkSetV6, cidr); err != nil {
				return fmt.Errorf("createTargetSet: unable to add ip %s to target networks ipset: %s", cidr, err)
			}
		}
	}

	return nil
}

// createProxySet creates a new target set -- ipportset is a list of {ip,port}
func (i *Instance) createProxySets(contextID string) error {
	proxyVIPSetV4, proxyVIPSetV6, proxyPortSet := i.getProxySet(contextID)

	_, err := i.ipset.NewIpset(proxyVIPSetV4, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", proxyVIPSetV4, err)
	}

	_, err = i.ipset.NewIpset(proxyVIPSetV6, "hash:net,port", &ipset.Params{HashFamily: "inet6"})
	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", proxyVIPSetV6, err)
	}

	err = i.createPUPortSet(proxyPortSet)

	if err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", proxyPortSet, err)
	}

	return nil
}

func (i *Instance) updateProxySet(contextID string, policy *policy.PUPolicy) error {

	dstSetNamev4, dstSetNamev6, srvSetName := i.getProxySet(contextID)

	vipTargetSet4 := ipset.IPSet{
		Name: dstSetNamev4,
	}
	vipTargetSet6 := ipset.IPSet{
		Name: dstSetNamev6,
	}

	if ferr := vipTargetSet4.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the vip proxy set")
	}

	if ferr := vipTargetSet6.Flush(); ferr != nil {
		zap.L().Warn("Unable to flush the vip proxy set")
	}

	for _, dependentService := range policy.DependentServices() {
		addresses := dependentService.NetworkInfo.Addresses
		min, max := dependentService.NetworkInfo.Ports.Range()
		for _, addr := range addresses {
			for i := int(min); i <= int(max); i++ {
				pair := addr.String() + "," + strconv.Itoa(i)
				if addr.IP.To4() != nil {
					if err := vipTargetSet4.Add(pair, 0); err != nil {
						return fmt.Errorf("unable to add dependent ip %s to target networks ipset: %s", pair, err)
					}
				} else {
					if err := vipTargetSet6.Add(pair, 0); err != nil {
						return fmt.Errorf("unable to add dependent ip %s to target networks ipset: %s", pair, err)
					}
				}
			}
		}
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
func (i *Instance) getProxySet(contextID string) (string, string, string) {
	puPortSetSuffix := puPortSetName(contextID, proxyPortSetPrefix)

	return "dst-ipv4-" + puPortSetSuffix, "dst-ipv6-" + puPortSetSuffix, "srv-" + puPortSetSuffix
}

//Not using ipset from coreos library they don't support bitmap:port
func ipsetCreatePortset(setname string) error {
	//Bitmap type is not supported by the ipset library
	path, _ := exec.LookPath("ipset")
	out, err := exec.Command(path, "create", setname, "bitmap:port", "range", "0-65535", "timeout", "0").CombinedOutput()
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
