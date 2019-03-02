package iptablesctrl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type tcpAutoPortSet struct {
	ipsetV4 string
	ipsetV6 string
}

func (i *Instance) getPortSet(ipt provider.IptablesProvider, contextID string) string {
	val, err := i.contextIDToPortSetMap.Get(contextID)
	if err != nil {
		return ""
	}

	tcpPortSet := val.(tcpAutoPortSet)

	if strings.Contains(tcpPortSet.ipsetV4, ipt.GetIpsetString()) {
		return tcpPortSet.ipsetV4
	}

	return tcpPortSet.ipsetV6
}

// createPortSets creates either UID or process port sets
func (i *Instance) createPortSet(contextID string, puInfo *policy.PUInfo) error {
	username := puInfo.Runtime.Options().UserID
	prefix := ""

	if username != "" {
		prefix = uidPortSetPrefix
	} else {
		prefix = processPortSetPrefix
	}

	portSetName := puPortSetName(contextID, prefix)

	portSetNameV4 := portSetName + i.iptV4.GetIpsetString()
	portSetNameV6 := portSetName + i.iptV6.GetIpsetString()

	if puseterr := i.createPUPortSet(portSetNameV4); puseterr != nil {
		return puseterr
	}

	if puseterr := i.createPUPortSet(portSetNameV6); puseterr != nil {
		return puseterr
	}

	i.contextIDToPortSetMap.AddOrUpdate(contextID, tcpAutoPortSet{ipsetV4: portSetNameV4, ipsetV6: portSetNameV6})
	return nil
}

func (i *Instance) deletePortSet(contextID string) error {

	portSetNameV4 := i.getPortSet(i.iptV4, contextID)
	portSetNameV6 := i.getPortSet(i.iptV6, contextID)

	if portSetNameV4 == "" || portSetNameV6 == "" {
		return fmt.Errorf("Failed to find port set")
	}

	ips := ipset.IPSet{
		Name: portSetNameV4,
	}

	if err := ips.Destroy(); err != nil {
		return fmt.Errorf("Failed to delete pu port set "+portSetNameV4, zap.Error(err))
	}

	ips = ipset.IPSet{
		Name: portSetNameV6,
	}

	if err := ips.Destroy(); err != nil {
		return fmt.Errorf("Failed to delete pu port set "+portSetNameV6, zap.Error(err))
	}

	if err := i.contextIDToPortSetMap.Remove(contextID); err != nil {
		zap.L().Debug("portset not found for the contextID", zap.String("contextID", contextID))
	}

	return nil
}

// DeletePortFromPortSet deletes ports from port sets
func (i *Instance) DeletePortFromPortSet(contextID string, port string) error {
	portSetName := i.getPortSet(i.iptV4, contextID)
	if portSetName == "" {
		return fmt.Errorf("unable to get portset for contextID %s", contextID)
	}

	ips := ipset.IPSet{
		Name: portSetName,
	}

	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}

	if err := ips.Del(port); err != nil {
		return fmt.Errorf("unable to delete port from portset: %s", err)
	}

	return nil
}

// AddPortToPortSet adds ports to the portsets
func (i *Instance) AddPortToPortSet(contextID string, port string) error {
	portSetName := i.getPortSet(i.iptV4, contextID)
	if portSetName == "" {
		return fmt.Errorf("unable to get portset for contextID %s", contextID)
	}

	ips := ipset.IPSet{
		Name: portSetName,
	}

	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}

	if err := ips.Add(port, 0); err != nil {
		return fmt.Errorf("unable to add port to portset: %s", err)
	}

	return nil
}
