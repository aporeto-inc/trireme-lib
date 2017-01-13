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
	mode                       int
}

// NewInstance creates a new iptables controller instance
func NewInstance(networkQueues, applicationQueues string, targetNetworks []string, mark int, remote bool, mode int) (*Instance, error) {

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
		mode: mode,
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
func (i *Instance) setPrefix(contextID string) (app, net string) {
	app = appChainPrefix + contextID + "-"
	net = netChainPrefix + contextID + "-"
	return app, net
}

// ConfigureRules implmenets the ConfigureRules interface
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy
	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	if policyrules == nil {
		return fmt.Errorf("No policy rules provided -nil ")
	}

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(version, appSetPrefix, netSetPrefix, policyrules.IngressACLs(), policyrules.EgressACLs(), ipAddress); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, ipAddresses *policy.IPMap, port string, mark string) error {

	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(ipAddresses.IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	i.delContainerFromSet(ipAddress)

	i.deleteAppSetRules(strconv.Itoa(version), appSetPrefix, ipAddress)
	i.deleteNetSetRules(strconv.Itoa(version), netSetPrefix, ipAddress)

	i.deleteSet(appSetPrefix + allowPrefix + strconv.Itoa(version))
	i.deleteSet(appSetPrefix + rejectPrefix + strconv.Itoa(version))
	i.deleteSet(netSetPrefix + allowPrefix + strconv.Itoa(version))
	i.deleteSet(netSetPrefix + rejectPrefix + strconv.Itoa(version))

	return nil

}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy
	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses().IPs)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(version, appSetPrefix, netSetPrefix, policyrules.IngressACLs(), policyrules.EgressACLs(), ipAddress); err != nil {
		return err
	}

	previousVersion := strconv.Itoa(version - 1)

	i.deleteAppSetRules(previousVersion, appSetPrefix, ipAddress)
	i.deleteNetSetRules(previousVersion, netSetPrefix, ipAddress)

	i.deleteSet(appSetPrefix + allowPrefix + previousVersion)
	i.deleteSet(appSetPrefix + rejectPrefix + previousVersion)
	i.deleteSet(netSetPrefix + allowPrefix + previousVersion)
	i.deleteSet(netSetPrefix + rejectPrefix + previousVersion)

	return nil

}

func (i *Instance) addAllRules(version int, appSetPrefix, netSetPrefix string, appACLs *policy.IPRuleList, netACLs *policy.IPRuleList, ip string) error {

	versionstring := strconv.Itoa(version)

	if err := i.addContainerToSet(ip); err != nil {
		return err
	}

	if err := i.createACLSets(versionstring, appSetPrefix, appACLs); err != nil {
		return err
	}

	if err := i.createACLSets(versionstring, netSetPrefix, netACLs); err != nil {
		return err
	}

	if err := i.addAppSetRules(versionstring, appSetPrefix, ip); err != nil {
		return err
	}

	if err := i.addNetSetRules(versionstring, netSetPrefix, ip); err != nil {
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
		"package": "ipsetctrl",
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
