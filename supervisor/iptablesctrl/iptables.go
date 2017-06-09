package iptablesctrl

import (
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"

	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	chainPrefix    = "TRIREME-"
	appChainPrefix = chainPrefix + "App-"
	netChainPrefix = chainPrefix + "Net-"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	networkQueues              string
	applicationQueues          string
	mark                       int
	ipt                        provider.IptablesProvider
	appPacketIPTableContext    string
	appAckPacketIPTableContext string
	appPacketIPTableSection    string
	netPacketIPTableContext    string
	netPacketIPTableSection    string
	appCgroupIPTableSection    string
	appSynAckIPTableSection    string
	mode                       constants.ModeType
}

// NewInstance creates a new iptables controller instance
func NewInstance(networkQueues, applicationQueues string, mark int, mode constants.ModeType) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize IPtables provider")
	}

	i := &Instance{
		networkQueues:     networkQueues,
		applicationQueues: applicationQueues,
		mark:              mark,
		ipt:               ipt,
		appPacketIPTableContext:    "raw",
		appAckPacketIPTableContext: "mangle",
		netPacketIPTableContext:    "mangle",
		mode: mode,
	}

	if mode == constants.LocalServer || mode == constants.RemoteContainer {
		i.appPacketIPTableSection = "OUTPUT" //nolint
		i.appCgroupIPTableSection = "OUTPUT" //nolint
		i.netPacketIPTableSection = "INPUT"  //nolint
		i.appSynAckIPTableSection = "OUTPUT" //nolint
	} else {
		i.appPacketIPTableSection = "PREROUTING"  //nolint
		i.appCgroupIPTableSection = "OUTPUT"      //nolint
		i.netPacketIPTableSection = "POSTROUTING" //nolint
		i.appSynAckIPTableSection = "INPUT"       //nolint
	}

	return i, nil

}

// chainPrefix returns the chain name for the specific PU
func (i *Instance) chainName(contextID string, version int) (app, net string) {
	app = appChainPrefix + contextID + "-" + strconv.Itoa(version)
	net = netChainPrefix + contextID + "-" + strconv.Itoa(version)
	return app, net
}

// DefaultIPAddress returns the default IP address for the processing unit
func (i *Instance) defaultIP(addresslist map[string]string) (string, bool) {

	if ip, ok := addresslist[policy.DefaultNamespace]; ok && len(ip) > 0 {
		return ip, true
	}

	if i.mode == constants.LocalContainer {
		return "0.0.0.0/0", false
	}

	return "0.0.0.0/0", true
}

// ConfigureRules implmenets the ConfigureRules interface
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy

	appChain, netChain := i.chainName(contextID, version)
	// policyrules.DefaultIPAddress()

	// Supporting only one ip
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found ")
	}

	// Configure all the ACLs
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	if i.mode != constants.LocalServer {

		if err := i.addChainRules(appChain, netChain, ipAddress, "", ""); err != nil {
			return err
		}

	} else {
		mark, ok := containerInfo.Runtime.Options().Get(cgnetcls.CgroupMarkTag)
		if !ok {
			return fmt.Errorf("No Mark value found")
		}

		port, ok := containerInfo.Runtime.Options().Get(cgnetcls.PortTag)
		if !ok {
			port = "0"
		}
		if err := i.addChainRules(appChain, netChain, ipAddress, port, mark); err != nil {
			return err
		}
	}

	if err := i.addPacketTrap(appChain, netChain, ipAddress, containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	if err := i.addAppACLs(appChain, ipAddress, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(netChain, ipAddress, policyrules.NetworkACLs()); err != nil {
		return err
	}

	if err := i.addExclusionACLs(appChain, netChain, ipAddress, policyrules.ExcludedNetworks()); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, ipAddresses *policy.IPMap, port string, mark string) error {
	var ipAddress string
	var ok bool

	// Supporting only one ip
	if i.mode != constants.LocalServer {
		if ipAddresses == nil {
			return fmt.Errorf("Provided map of IP addresses is nil")
		}

		ipAddress, ok = i.defaultIP(ipAddresses.IPs)
		if !ok {
			return fmt.Errorf("No ip address found ")
		}
	}

	appChain, netChain := i.chainName(contextID, version)

	if derr := i.deleteChainRules(appChain, netChain, ipAddress, port, mark); derr != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(derr))
	}

	if err := i.deleteAllContainerChains(appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	return nil
}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo) error {

	if containerInfo == nil {
		return fmt.Errorf("Container info cannot be nil")
	}

	policyrules := containerInfo.Policy
	if policyrules == nil {
		return fmt.Errorf("Policy rules cannot be nil")
	}

	// Supporting only one ip
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found ")
	}

	appChain, netChain := i.chainName(contextID, version)

	oldAppChain, oldNetChain := i.chainName(contextID, version^1)

	//Add a new chain for this update and map all rules there
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	if err := i.addPacketTrap(appChain, netChain, ipAddress, containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	if err := i.addAppACLs(appChain, ipAddress, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(netChain, ipAddress, policyrules.NetworkACLs()); err != nil {
		return err
	}

	if err := i.addExclusionACLs(appChain, netChain, ipAddress, policyrules.ExcludedNetworks()); err != nil {
		return err
	}

	// Add mapping to new chain
	if i.mode != constants.LocalServer {

		if err := i.addChainRules(appChain, netChain, ipAddress, "", ""); err != nil {
			return err
		}
	} else {
		mark, ok := containerInfo.Runtime.Options().Get(cgnetcls.CgroupMarkTag)
		if !ok {
			return fmt.Errorf("No Mark value found")
		}
		portlist, ok := containerInfo.Runtime.Options().Get(cgnetcls.PortTag)
		if !ok {
			portlist = "0"
		}

		if err := i.addChainRules(appChain, netChain, ipAddress, portlist, mark); err != nil {
			return err
		}
	}

	//Remove mapping from old chain
	if i.mode != constants.LocalServer {
		if err := i.deleteChainRules(oldAppChain, oldNetChain, ipAddress, "", ""); err != nil {
			return err
		}
	} else {
		mark, _ := containerInfo.Runtime.Options().Get(cgnetcls.CgroupMarkTag)
		port, ok := containerInfo.Runtime.Options().Get(cgnetcls.PortTag)
		if !ok {
			port = "0"
		}
		if err := i.deleteChainRules(oldAppChain, oldNetChain, ipAddress, port, mark); err != nil {
			return err
		}
	}

	// Delete the old chain to clean up
	if err := i.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		return err
	}

	return nil
}

// Start starts the iptables controller
func (i *Instance) Start() error {

	// Clean any previous ACLs
	if err := i.cleanACLs(); err != nil {
		zap.L().Warn("Failed to clean previous acls while starting the supervisor", zap.Error(err))
	}

	if i.mode == constants.LocalContainer {
		if i.acceptMarkedPackets() != nil {
			return fmt.Errorf("Filter of marked packets was not set")
		}
	}

	zap.L().Debug("Started the iptables controller")

	return nil
}

// SetTargetNetworks updates ths target networks for SynAck packets
func (i *Instance) SetTargetNetworks(current, networks []string) error {

	// Cleanup old ACLs
	if len(current) > 0 {
		if err := i.CleanCaptureSynAckPackets(current); err != nil {
			return fmt.Errorf("Failed to clean synack networks")
		}
	}

	// Insert new ACLs
	if err := i.captureTargetSynAckPackets(i.appPacketIPTableSection, i.netPacketIPTableSection, networks); err != nil {
		return fmt.Errorf("Failed to update synack networks")
	}

	return nil
}

// Stop stops the supervisor
func (i *Instance) Stop() error {

	zap.L().Debug("Stop the supervisor")

	// Clean any previous ACLs that we have installed
	if err := i.cleanACLs(); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	return nil
}
