package iptablesctrl

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
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
	targetNetworks             []string
	mark                       int
	ipt                        provider.IptablesProvider
	appPacketIPTableContext    string
	appAckPacketIPTableContext string
	appPacketIPTableSection    string
	netPacketIPTableContext    string
	netPacketIPTableSection    string
	remote                     bool
}

// NewInstance creates a new iptables controller instance
func NewInstance(networkQueues, applicationQueues string, targetNetworks []string, mark int, remote bool) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize IPtables provider")
	}

	i := &Instance{
		networkQueues:     networkQueues,
		applicationQueues: applicationQueues,
		targetNetworks:    targetNetworks,
		mark:              mark,
		ipt:               ipt,
		appPacketIPTableContext:    "raw",
		appAckPacketIPTableContext: "mangle",
		netPacketIPTableContext:    "mangle",
		remote:                     remote,
	}

	if remote {
		i.appPacketIPTableSection = "OUTPUT"
		i.netPacketIPTableSection = "INPUT"
	} else {
		i.appPacketIPTableSection = "PREROUTING"
		i.netPacketIPTableSection = "POSTROUTING"
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

	if ip, ok := addresslist[policy.DefaultNamespace]; ok {
		return ip, true
	}

	return "0.0.0.0/0", i.remote
}

// ConfigureRules implmenets the ConfigureRules interface
func (i *Instance) ConfigureRules(version int, contextID string, policyrules *policy.PUPolicy) error {

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

	if err := i.addChainRules(appChain, netChain, ipAddress); err != nil {
		return err
	}

	if err := i.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		return err
	}

	if err := i.addAppACLs(appChain, ipAddress, policyrules.IngressACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(netChain, ipAddress, policyrules.EgressACLs()); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, ipAddresses *policy.IPMap) error {

	// Supporting only one ip
	if ipAddresses == nil {
		return fmt.Errorf("Provided map of IP addresses is nil")
	}

	ipAddress, ok := i.defaultIP(ipAddresses.IPs)
	if !ok {
		return fmt.Errorf("No ip address found ")
	}

	appChain, netChain := i.chainName(contextID, version)

	i.deleteChainRules(appChain, netChain, ipAddress)

	i.deleteAllContainerChains(appChain, netChain)

	return nil
}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, policyrules *policy.PUPolicy) error {

	if policyrules == nil {
		return fmt.Errorf("Policy rules cannot be nil")
	}

	// Supporting only one ip
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found ")
	}

	appChain, netChain := i.chainName(contextID, version)

	oldAppChain, oldNetChain := i.chainName(contextID, version-1)

	//Add a new chain for this update and map all rules there
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	if err := i.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		return err
	}

	if err := i.addAppACLs(appChain, ipAddress, policyrules.IngressACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(netChain, ipAddress, policyrules.EgressACLs()); err != nil {
		return err
	}

	// Add mapping to new chain
	if err := i.addChainRules(appChain, netChain, ipAddress); err != nil {
		return err
	}

	//Remove mapping from old chain
	if err := i.deleteChainRules(oldAppChain, oldNetChain, ipAddress); err != nil {
		return err
	}

	// Delete the old chain to clean up
	if err := i.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		return err
	}

	return nil
}

// Start starts the iptables controller
func (i *Instance) Start() error {
	log.WithFields(log.Fields{
		"package": "iptablesctrl",
	}).Debug("Start the supervisor")

	// Clean any previous ACLs
	i.cleanACLs()

	if i.acceptMarkedPackets() != nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Debug("Cannot filter marked packets. Abort")

		return fmt.Errorf("Filter of marked packets was not set")
	}

	return nil
}

// Stop stops the supervisor
func (i *Instance) Stop() error {
	log.WithFields(log.Fields{
		"package": "iptablesctrl",
	}).Debug("Stop the supervisor")

	// Clean any previous ACLs that we have installed
	i.cleanACLs()
	return nil
}

// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
func (i *Instance) AddExcludedIP(ip string) error {

	return i.addExclusionChainRules(ip)
}

// RemoveExcludedIP removes the exception for the destion IP given in parameter.
func (i *Instance) RemoveExcludedIP(ip string) error {

	return i.deleteExclusionChainRules(ip)
}
