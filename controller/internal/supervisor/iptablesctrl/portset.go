package iptablesctrl

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

func (i *Instance) getPortSet(contextID string) string {
	portset, err := i.contextIDToPortSetMap.Get(contextID)
	if err != nil {
		return ""
	}

	return portset.(string)
}

// createPortSets creates either UID or process port sets. This is only
// needed for Linux PUs and it returns immediately for container PUs.
func (i *Instance) createPortSet(contextID string, puInfo *policy.PUInfo) error {

	if i.mode == constants.RemoteContainer {
		return nil
	}

	username := puInfo.Runtime.Options().UserID
	prefix := ""

	if username != "" {
		prefix = uidPortSetPrefix
	} else {
		prefix = processPortSetPrefix
	}

	portSetName := puPortSetName(contextID, prefix)

	if puseterr := i.createPUPortSet(portSetName); puseterr != nil {
		return puseterr
	}

	i.contextIDToPortSetMap.AddOrUpdate(contextID, portSetName)
	return nil
}

// deletePortSet delets the ports set that was created for a Linux PU.
// It returns without errors for container PUs.
func (i *Instance) deletePortSet(contextID string) error {

	if i.mode == constants.RemoteContainer {
		return nil
	}

	portSetName := i.getPortSet(contextID)
	if portSetName == "" {
		return fmt.Errorf("Failed to find port set")
	}

	ips := ipset.IPSet{
		Name: portSetName,
	}

	if err := ips.Destroy(); err != nil {
		return fmt.Errorf("Failed to delete pu port set "+portSetName, zap.Error(err))
	}

	if err := i.contextIDToPortSetMap.Remove(contextID); err != nil {
		zap.L().Debug("portset not found for the contextID", zap.String("contextID", contextID))
	}

	return nil
}

// DeletePortFromPortSet deletes ports from port sets
func (i *Instance) DeletePortFromPortSet(contextID string, port string) error {
	portSetName := i.getPortSet(contextID)
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
	portSetName := i.getPortSet(contextID)
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
