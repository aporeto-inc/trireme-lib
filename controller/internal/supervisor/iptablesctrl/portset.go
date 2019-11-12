package iptablesctrl

import (
	"fmt"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

func (i *iptables) getPortSet(contextID string) string {
	portset, err := i.contextIDToPortSetMap.Get(contextID)
	if err != nil {
		return ""
	}

	return portset.(string)
}

// createPortSets creates either UID or process port sets. This is only
// needed for Linux PUs and it returns immediately for container PUs.
func (i *iptables) createPortSet(contextID string, username string) error {

	if i.mode == constants.RemoteContainer {
		return nil
	}

	ipsetPrefix := i.impl.GetIPSetPrefix()
	prefix := ""
	if username != "" {
		prefix = ipsetPrefix + uidPortSetPrefix
	} else {
		prefix = ipsetPrefix + processPortSetPrefix
	}
	portSetName := puPortSetName(contextID, prefix)

	_, err := i.ipset.NewIpset(portSetName, portSetIpsetType, nil)
	if err != nil {
		return err
	}

	i.contextIDToPortSetMap.AddOrUpdate(contextID, portSetName)
	return nil
}

// deletePortSet delets the ports set that was created for a Linux PU.
// It returns without errors for container PUs.
func (i *iptables) deletePortSet(contextID string) error {

	if i.mode == constants.RemoteContainer {
		return nil
	}

	portSetName := i.getPortSet(contextID)
	if portSetName == "" {
		return fmt.Errorf("Failed to find port set")
	}

	ips := i.ipset.GetIpset(portSetName)
	if err := ips.Destroy(); err != nil {
		return fmt.Errorf("Failed to delete pu port set "+portSetName, zap.Error(err))
	}

	if err := i.contextIDToPortSetMap.Remove(contextID); err != nil {
		zap.L().Debug("portset not found for the contextID", zap.String("contextID", contextID))
	}

	return nil
}

// DeletePortFromPortSet deletes ports from port sets
func (i *iptables) DeletePortFromPortSet(contextID string, port string) error {

	portSetName := i.getPortSet(contextID)
	if portSetName == "" {
		return fmt.Errorf("unable to get portset for contextID %s", contextID)
	}

	ips := i.ipset.GetIpset(portSetName)
	if err := ips.Del(port); err != nil {
		return fmt.Errorf("unable to delete port from portset: %s", err)
	}

	return nil
}

// DeletePortFromPortSet deletes ports from port sets
func (i *Instance) DeletePortFromPortSet(contextID string, port string) error {

	if err := i.iptv4.DeletePortFromPortSet(contextID, port); err != nil {
		zap.L().Warn("Failed to delete port from ipv4 portset ", zap.String("contextID", contextID), zap.String("port", port), zap.Error(err))
	}

	if err := i.iptv6.DeletePortFromPortSet(contextID, port); err != nil {
		zap.L().Warn("Failed to delete port from ipv6 portset ", zap.String("port", port), zap.Error(err))
	}

	return nil
}

// AddPortToPortSet adds ports to the portsets
func (i *iptables) AddPortToPortSet(contextID string, port string) error {

	portSetName := i.getPortSet(contextID)
	if portSetName == "" {
		return fmt.Errorf("unable to get portset for contextID %s", contextID)
	}
	ips := i.ipset.GetIpset(portSetName)
	if err := ips.Add(port, 0); err != nil {
		return fmt.Errorf("unable to add port to portset: %s", err)
	}

	return nil
}

// AddPortToPortSet adds ports to the portsets
func (i *Instance) AddPortToPortSet(contextID string, port string) error {

	if err := i.iptv4.AddPortToPortSet(contextID, port); err != nil {
		zap.L().Warn("Failed to add port to ipv4 portset", zap.String("contextID", contextID), zap.String("port", port), zap.Error(err))
	}

	if err := i.iptv6.AddPortToPortSet(contextID, port); err != nil {
		zap.L().Warn("Failed to add port to ipv6 portset", zap.String("contextID", contextID), zap.String("port", port), zap.Error(err))
	}

	return nil
}
