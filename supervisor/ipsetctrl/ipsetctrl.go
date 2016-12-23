package ipsetctrl

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	triremeSet   = "TriremeSet"
	containerSet = "ContainerSet"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	networkQueues              string
	applicationQueues          string
	targetNetworks             []string
	mark                       int
	ipt                        provider.IptablesProvider
	ips                        provider.IpsetProvider
	targetSet                  provider.Ipset
	containerSet               provider.Ipset
	appPacketIPTableContext    string
	appAckPacketIPTableContext string
	appPacketIPTableSection    string
	netPacketIPTableContext    string
	netPacketIPTableSection    string
}

// NewInstance creates a new iptables controller instance
func NewInstance(networkQueues, applicationQueues string, targetNetworks []string, mark int, remote bool) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize IPtables provider")
	}

	ips := provider.NewGoIPsetProvider()

	i := &Instance{
		networkQueues:     networkQueues,
		applicationQueues: applicationQueues,
		targetNetworks:    targetNetworks,
		mark:              mark,
		ipt:               ipt,
		ips:               ips,
		appPacketIPTableContext:    "raw",
		appAckPacketIPTableContext: "mangle",
		netPacketIPTableContext:    "mangle",
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

// DefaultIPAddress returns the default IP address for the processing unit
func (i *Instance) defaultIP(addresslist map[string]string) (string, bool) {

	if ip, ok := addresslist[policy.DefaultNamespace]; ok {
		return ip, true
	}

	return "0.0.0.0/0", false
}

// chainPrefix returns the chain name for the specific PU
func (i *Instance) chainName(contextID string, version int) (app, net string) {
	app = appChainPrefix + contextID + "-" + strconv.Itoa(version)
	net = netChainPrefix + contextID + "-" + strconv.Itoa(version)
	return app, net
}

// ConfigureRules implmenets the ConfigureRules interface
func (i *Instance) ConfigureRules(version int, contextID string, policyrules *policy.PUPolicy) error {

	appSet, netSet := i.chainName(contextID, version)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(contextID, appSet, netSet, policyrules.IngressACLs(), policyrules.EgressACLs(), ipAddress); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, ipAddresses *policy.IPMap) error {

	appSet, netSet := i.chainName(contextID, version)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(ipAddresses.IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	i.deleteAppSetRule(appSet, ipAddress)

	i.deleteNetSetRule(netSet, ipAddress)

	i.deleteSet(appSet)

	i.deleteSet(netSet)

	return nil

}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, policyrules *policy.PUPolicy) error {

	appSet, netSet := i.chainName(contextID, version)
	oldAppSet, oldNetSet := i.chainName(contextID, version-1)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(contextID, appSet, netSet, policyrules.IngressACLs(), policyrules.EgressACLs(), ipAddress); err != nil {
		return err
	}

	i.delContainerFromSet(ipAddress)

	i.deleteAppSetRule(oldAppSet, ipAddress)

	i.deleteNetSetRule(oldNetSet, ipAddress)

	i.deleteSet(oldAppSet)

	i.deleteSet(oldNetSet)

	return nil

}

func (i *Instance) addAllRules(contextID string, appSet string, netSet string, appACLs *policy.IPRuleList, netACLs *policy.IPRuleList, ip string) error {

	if err := i.addContainerToSet(ip); err != nil {
		return err
	}

	if err := i.createACLSets(appSet, appACLs); err != nil {
		return err
	}

	if err := i.createACLSets(netSet, netACLs); err != nil {
		return err
	}

	if err := i.addAppSetRule(appSet, ip); err != nil {
		return err
	}

	if err := i.addNetSetRule(netSet, ip); err != nil {
		return err
	}
	return nil
}

// Start implements the start of the interface
func (i *Instance) Start() error {
	if err := i.setupIpset(triremeSet, containerSet); err != nil {
		return err
	}
	if err := i.setupTrapRules(triremeSet); err != nil {
		return err
	}
	return nil
}

// Stop implements the stop interface
func (i *Instance) Stop() error {
	i.cleanACLs()
	return nil
}

func (i *Instance) cleanACLs() error {
	log.WithFields(log.Fields{
		"package": "supervisor",
	}).Debug("Cleaning all IPTables")

	// Clean Application Rules/Chains
	// i.cleanACLs()

	i.cleanIPSets()

	return nil
}

// AddExcludedIP implements the interface
func (i *Instance) AddExcludedIP(ip string) error {

	return i.addIpsetOption(ip)
}

// RemoveExcludedIP implements the interface
func (i *Instance) RemoveExcludedIP(ip string) error {

	return i.deleteIpsetOption(ip)
}
