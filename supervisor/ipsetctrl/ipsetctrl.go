package ipsetctrl

import (
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

const (
	triremeSet   = "TriremeSet"
	containerSet = "ContainerSet"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	fqc                        *fqconfig.FilterQueue
	ipt                        provider.IptablesProvider
	ips                        provider.IpsetProvider
	targetSet                  provider.Ipset
	containerSet               provider.Ipset
	appPacketIPTableContext    string
	appAckPacketIPTableContext string
	appPacketIPTableSection    string
	netPacketIPTableContext    string
	netPacketIPTableSection    string
	mode                       constants.ModeType
}

// NewInstance creates a new iptables controller instance
func NewInstance(fqc *fqconfig.FilterQueue, remote bool, mode constants.ModeType) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize IPtables provider")
	}

	ips := provider.NewGoIPsetProvider()

	i := &Instance{
		fqc: fqc,
		ipt: ipt,
		ips: ips,
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

	if containerInfo == nil {
		return fmt.Errorf("Container info cannot be nil")
	}

	policyrules := containerInfo.Policy
	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	if policyrules == nil {
		return fmt.Errorf("No policy rules provided -nil ")
	}

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses())
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(version, appSetPrefix, netSetPrefix, policyrules.ApplicationACLs(), policyrules.NetworkACLs(), ipAddress); err != nil {
		return err
	}

	if err := i.addTargetNets(containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, ipAddresses policy.ExtendedMap, port string, mark string, uid string) error {

	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(ipAddresses)
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	var errvector [8]error

	errvector[0] = i.delContainerFromSet(ipAddress)

	errvector[1] = i.deleteAppSetRules(strconv.Itoa(version), appSetPrefix, ipAddress)
	errvector[2] = i.deleteNetSetRules(strconv.Itoa(version), netSetPrefix, ipAddress)

	errvector[3] = i.deleteSet(appSetPrefix + allowPrefix + strconv.Itoa(version))
	errvector[4] = i.deleteSet(appSetPrefix + rejectPrefix + strconv.Itoa(version))
	errvector[5] = i.deleteSet(netSetPrefix + allowPrefix + strconv.Itoa(version))
	errvector[6] = i.deleteSet(netSetPrefix + rejectPrefix + strconv.Itoa(version))

	for i := 0; i < 7; i++ {
		if errvector[i] != nil {
			zap.L().Warn("Error while deleting rules", zap.Error(errvector[i]))
		}
	}
	return nil

}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy
	appSetPrefix, netSetPrefix := i.setPrefix(contextID)

	// Currently processing only containers with one IP address
	ipAddress, ok := i.defaultIP(policyrules.IPAddresses())
	if !ok {
		return fmt.Errorf("No ip address found")
	}

	if err := i.addAllRules(version, appSetPrefix, netSetPrefix, policyrules.ApplicationACLs(), policyrules.NetworkACLs(), ipAddress); err != nil {
		return fmt.Errorf("Unable to add all rules: %s", err)
	}

	previousVersion := strconv.Itoa(version - 1)

	var errvector [6]error

	errvector[0] = i.deleteAppSetRules(previousVersion, appSetPrefix, ipAddress)
	errvector[1] = i.deleteNetSetRules(previousVersion, netSetPrefix, ipAddress)

	errvector[2] = i.deleteSet(appSetPrefix + allowPrefix + previousVersion)
	errvector[3] = i.deleteSet(appSetPrefix + rejectPrefix + previousVersion)
	errvector[4] = i.deleteSet(netSetPrefix + allowPrefix + previousVersion)
	errvector[5] = i.deleteSet(netSetPrefix + rejectPrefix + previousVersion)

	for i := 0; i < 6; i++ {
		if errvector[i] != nil {
			zap.L().Warn("Error while deleting rules", zap.Error(errvector[i]))
		}
	}

	return nil

}

func (i *Instance) addAllRules(version int, appSetPrefix, netSetPrefix string, appACLs policy.IPRuleList, netACLs policy.IPRuleList, ip string) error {

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

	return i.cleanACLs()
}

// SetTargetNetworks sets the target networks
func (i *Instance) SetTargetNetworks(current, networks []string) error {
	return nil
}

func (i *Instance) cleanACLs() error {

	zap.L().Debug("Cleaning all IPTables")

	if err := i.cleanIPSets(); err != nil {
		zap.L().Warn("Error while cleaning ACL rules", zap.Error(err))
	}

	return nil
}

// AddExcludedIP implements the interface
func (i *Instance) AddExcludedIP(ipList []string) error {
	for _, ip := range ipList {
		return i.addIpsetOption(ip)
	}
	return nil
}

// RemoveExcludedIP implements the interface
func (i *Instance) RemoveExcludedIP(ipList []string) error {
	for _, ip := range ipList {
		return i.deleteIpsetOption(ip)
	}
	return nil

}
