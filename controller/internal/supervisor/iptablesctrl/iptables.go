package iptablesctrl

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

const (
	uidchain                 = "UIDCHAIN"
	uidInput                 = "UIDInput"
	chainPrefix              = "TRIREME-"
	appChainPrefix           = chainPrefix + "App-"
	netChainPrefix           = chainPrefix + "Net-"
	targetNetworkSetV4       = "TargetNetSetV4"
	targetNetworkSetV6       = "TargetNetSetV6"
	uidPortSetPrefix         = "UIDPort-"
	processPortSetPrefix     = "ProcessPort-"
	proxyPortSetPrefix       = "Proxy-"
	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionInput      = "INPUT"
	ipTableSectionPreRouting = "PREROUTING"
	natProxyOutputChain      = "RedirProxy-App"
	natProxyInputChain       = "RedirProxy-Net"
	proxyOutputChain         = "Proxy-App"
	proxyInputChain          = "Proxy-Net"
	proxyMark                = "0x40"

	// TriremeInput represent the chain that contains pu input rules.
	TriremeInput = "Trireme-Input"
	// TriremeOutput represent the chain that contains pu output rules.
	TriremeOutput = "Trireme-Output"

	// NetworkSvcInput represent the chain that contains NetworkSvc input rules.
	NetworkSvcInput = "NetworkSvc-Input"

	// NetworkSvcOutput represent the chain that contains NetworkSvc output rules.
	NetworkSvcOutput = "NetworkSvc-Output"

	// HostModeInput represent the chain that contains Hostmode input rules.
	HostModeInput = "Hostmode-Input"

	// HostModeOutput represent the chain that contains Hostmode output rules.
	HostModeOutput = "Hostmode-Output"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	fqc                     *fqconfig.FilterQueue
	iptV4                   provider.IptablesProvider
	iptV6                   provider.IptablesProvider
	ipset                   provider.IpsetProvider
	targetSet               bool
	appPacketIPTableContext string
	appProxyIPTableContext  string
	appPacketIPTableSection string
	netPacketIPTableContext string
	netPacketIPTableSection string
	netLinuxIPTableSection  string
	appCgroupIPTableSection string
	appSynAckIPTableSection string
	mode                    constants.ModeType
	contextIDToPortSetMap   cache.DataStore
	createPUPortSet         func(string) error
	isLegacyKernel          bool
	serviceIDToIPsets       map[string]*ipsetInfo
	puToServiceIDs          map[string][]string
}

var instance *Instance
var lock sync.RWMutex

// GetInstance returns the instance of the iptables object
func GetInstance() *Instance {
	lock.Lock()
	defer lock.Unlock()
	return instance
}

// NewInstance creates a new iptables controller instance
func NewInstance(fqc *fqconfig.FilterQueue, mode constants.ModeType) (*Instance, error) {

	iptV4, err := provider.NewGoIPTablesProviderV4([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	iptV6, err := provider.NewGoIPTablesProviderV6([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	ips := provider.NewGoIPsetProvider()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ipsets: %s", err)
	}

	i := &Instance{
		fqc:                     fqc,
		iptV4:                   iptV4,
		iptV6:                   iptV6,
		ipset:                   ips,
		appPacketIPTableContext: "mangle",
		netPacketIPTableContext: "mangle",
		appProxyIPTableContext:  "nat",
		mode:                    mode,
		appPacketIPTableSection: ipTableSectionOutput,
		appCgroupIPTableSection: TriremeOutput,
		netLinuxIPTableSection:  TriremeInput,
		netPacketIPTableSection: ipTableSectionInput,
		appSynAckIPTableSection: ipTableSectionOutput,
		contextIDToPortSetMap:   cache.NewCache("contextIDToPortSetMap"),
		createPUPortSet:         ipsetCreatePortset,
		isLegacyKernel:          buildflags.IsLegacyKernel(),
		serviceIDToIPsets:       map[string]*ipsetInfo{},
		puToServiceIDs:          map[string][]string{},
	}

	lock.Lock()
	instance = i
	defer lock.Unlock()

	return i, nil
}

// chainPrefix returns the chain name for the specific PU.
func (i *Instance) chainName(contextID string, version int) (app, net string, err error) {
	hash := md5.New()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return "", "", err
	}
	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	if len(contextID) > 4 {
		contextID = contextID[:4] + output[:6]
	} else {
		contextID = contextID + output[:6]
	}

	app = appChainPrefix + contextID + "-" + strconv.Itoa(version)
	net = netChainPrefix + contextID + "-" + strconv.Itoa(version)

	return app, net, nil
}

func (i *Instance) installIPv4Rules(contextID, appChain, netChain string, containerInfo *policy.PUInfo, appACLIPset, netACLIPset []aclIPset) error {

	proxyVIPSetV4, _, proxyPortSet := i.getProxySet(contextID)

	if err := i.installRules(i.iptV4, contextID, appChain, netChain, proxyVIPSetV4, proxyPortSet, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	if err := i.addAppRulesV4(contextID, appChain); err != nil {
		return err
	}

	if err := i.addNetRulesV4(contextID, netChain); err != nil {
		return err
	}

	if err := i.iptV4.Commit(); err != nil {
		return err
	}

	return nil
}

func (i *Instance) installIPv6Rules(contextID, appChain, netChain string, containerInfo *policy.PUInfo, appACLIPset, netACLIPset []aclIPset) error {

	_, proxyVIPSetV6, proxyPortSet := i.getProxySet(contextID)

	if err := i.installRules(i.iptV6, contextID, appChain, netChain, proxyVIPSetV6, proxyPortSet, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	if err := i.addAppRulesV6(contextID, appChain); err != nil {
		return err
	}

	if err := i.addNetRulesV6(contextID, netChain); err != nil {
		return err
	}

	if err := i.iptV6.Commit(); err != nil {
		return err
	}

	return nil
}

// ConfigureRules implments the ConfigureRules interface. It will create the
// port sets and then it will call install rules to create all the ACLs for
// the given chains. PortSets are only created here. Updates will use the
// exact same logic.
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	var appACLIPset, netACLIPset []aclIPset

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	// Create the proxy sets.
	if err := i.createProxySets(contextID); err != nil {
		return err
	}

	if err := i.createPortSet(contextID, containerInfo); err != nil {
		return err
	}

	if err := i.updateProxySet(contextID, containerInfo.Policy); err != nil {
		return err
	}

	if appACLIPset, err = i.createACLIPSets(contextID, containerInfo.Policy.ApplicationACLs()); err != nil {
		return err
	}

	if netACLIPset, err = i.createACLIPSets(contextID, containerInfo.Policy.NetworkACLs()); err != nil {
		return err
	}

	if err := i.installIPv4Rules(contextID, appChain, netChain, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	if err := i.installIPv6Rules(contextID, appChain, netChain, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, puType string, exclusions []string) error {

	tcpPortSetName := i.getPortSet(contextID)

	proxyVIPSetV4, proxyVIPSetV6, proxyPortSet := i.getProxySet(contextID)

	if tcpPortSetName == "" {
		zap.L().Error("port set name can not be nil")
	}

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		// Don't return here we can still try and reclaims portset and targetnetwork sets
		zap.L().Error("Count not generate chain name", zap.Error(err))
	}

	if err := i.deleteChainRules(i.iptV4, contextID, tcpPortSetName, appChain, netChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyVIPSetV4, proxyPortSet, puType); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	if err := i.deleteChainRules(i.iptV6, contextID, tcpPortSetName, appChain, netChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyVIPSetV6, proxyPortSet, puType); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	if i.isLegacyKernel {
		if err = i.deleteLegacyNATExclusionACLs(contextID, mark, exclusions, tcpPorts); err != nil {
			zap.L().Warn("Failed to clean up legacy NAT exclusions", zap.Error(err))
		}

	} else {
		if err = i.deleteNATExclusionACLs(contextID, mark, exclusions); err != nil {
			zap.L().Warn("Failed to clean up NAT exclusions", zap.Error(err))
		}
	}

	if err = i.deleteAllContainerChains(i.iptV4, appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	if err = i.deleteAllContainerChains(i.iptV6, appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	if err := i.iptV4.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	if err := i.iptV6.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	if err := i.deletePortSet(contextID); err != nil {
		zap.L().Warn("Failed to remove port set")
	}

	if err := i.deleteProxySets(contextID); err != nil {
		zap.L().Warn("Failed to delete proxy sets", zap.Error(err))
	}

	i.destroyACLIPsets(contextID)

	return nil
}

// UpdateRules implements the update part of the interface. Update will call
// installrules to install the new rules and then it will delete the old rules.
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	var appACLIPset, netACLIPset []aclIPset

	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}
	portSetName := i.getPortSet(contextID)

	proxyPort := containerInfo.Policy.ServicesListeningPort()
	proxyVIPSetV4, proxyVIPSetV6, proxyPortSet := i.getProxySet(contextID)

	if portSetName == "" {
		zap.L().Error("port set name for contextID does not exist. This should not happen")
	}

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	oldAppChain, oldNetChain, err := i.chainName(contextID, version^1)

	if err != nil {
		return err
	}

	// If local server, install pu specific chains in Trireme/Hostmode chains.
	puType := extractors.GetPuType(containerInfo.Runtime)
	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(containerInfo.Runtime.Options().Services)

	if appACLIPset, err = i.createACLIPSets(contextID, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if netACLIPset, err = i.createACLIPSets(contextID, policyrules.NetworkACLs()); err != nil {
		return err
	}

	if err := i.installIPv4Rules(contextID, appChain, netChain, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	if err := i.installIPv6Rules(contextID, appChain, netChain, containerInfo, appACLIPset, netACLIPset); err != nil {
		return err
	}

	// Remove mapping from old chain
	if i.mode != constants.LocalServer {
		if err := i.deleteChainRules(i.iptV4, contextID, portSetName, oldAppChain, oldNetChain, "", "", "", "", proxyPort, proxyVIPSetV4, proxyPortSet, puType); err != nil {
			return err
		}
		if err := i.deleteChainRules(i.iptV6, contextID, portSetName, oldAppChain, oldNetChain, "", "", "", "", proxyPort, proxyVIPSetV6, proxyPortSet, puType); err != nil {
			return err
		}
	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		username := containerInfo.Runtime.Options().UserID

		if err := i.deleteChainRules(i.iptV4, contextID, portSetName, oldAppChain, oldNetChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyVIPSetV4, proxyPortSet, puType); err != nil {
			return err
		}

		if err := i.deleteChainRules(i.iptV6, contextID, portSetName, oldAppChain, oldNetChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyVIPSetV6, proxyPortSet, puType); err != nil {
			return err
		}
	}

	mark := ""
	if containerInfo.Runtime != nil {
		mark = containerInfo.Runtime.Options().CgroupMark
	}

	excludedNetworks := []string{}
	if oldContainerInfo != nil && oldContainerInfo.Policy != nil {
		excludedNetworks = oldContainerInfo.Policy.ExcludedNetworks()
	}

	if i.isLegacyKernel {
		if err := i.deleteLegacyNATExclusionACLs(contextID, mark, excludedNetworks, tcpPorts); err != nil {
			zap.L().Warn("Failed to clean up legacy NAT exclusions", zap.Error(err))
		}

	} else {
		if err := i.deleteNATExclusionACLs(contextID, mark, excludedNetworks); err != nil {
			zap.L().Warn("Failed to clean up NAT exclusions", zap.Error(err))
		}
	}
	// Delete the old chain to clean up
	if err := i.deleteAllContainerChains(i.iptV4, oldAppChain, oldNetChain); err != nil {
		return err
	}

	if err := i.deleteAllContainerChains(i.iptV6, oldAppChain, oldNetChain); err != nil {
		return err
	}

	if err = i.iptV4.Commit(); err != nil {
		return err
	}

	if err = i.iptV6.Commit(); err != nil {
		return err
	}

	i.synchronizePUACLs(contextID, policyrules.ApplicationACLs(), policyrules.NetworkACLs())

	return nil
}

// Run starts the iptables controller
func (i *Instance) Run(ctx context.Context) error {

	// Clean any previous ACLs
	if err := i.cleanACLs(i.iptV4); err != nil {
		zap.L().Warn("Unable to clean previous acls while starting the supervisor", zap.Error(err))
	}

	if err := i.cleanACLs(i.iptV6); err != nil {
		zap.L().Warn("Unable to clean previous acls while starting the supervisor", zap.Error(err))
	}

	if err := i.InitializeChains(i.iptV4); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	if err := i.InitializeChains(i.iptV6); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	go func() {
		<-ctx.Done()
		zap.L().Debug("Stop the supervisor")

		i.CleanUp() // nolint
	}()

	zap.L().Debug("Started the iptables controller")

	return nil
}

// CleanUp requires the implementor to clean up all ACLs
func (i *Instance) CleanUp() error {

	if err := i.cleanACLs(i.iptV4); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	if err := i.cleanACLs(i.iptV6); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	if err := i.ipset.DestroyAll(); err != nil {
		zap.L().Error("Failed to clean up ipsets", zap.Error(err))
	}

	return nil
}

// SetTargetNetworks updates ths target networks for SynAck packets
func (i *Instance) SetTargetNetworks(current, networks []string) error {

	// Cleanup old ACLs
	if len(current) > 0 && i.targetSet {
		return i.updateTargetNetworks(current, networks)
	}

	// Create the target network set
	if err := i.createTargetSet(networks); err != nil {
		return err
	}

	// Insert the ACLS that point to the target networks
	if err := i.setGlobalRules(i.iptV4, i.appPacketIPTableSection, i.netPacketIPTableSection); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	if err := i.setGlobalRules(i.iptV6, i.appPacketIPTableSection, i.netPacketIPTableSection); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	return nil
}

// InitializeChains initializes the chains.
func (i *Instance) InitializeChains(ipt provider.IptablesProvider) error {

	if i.mode == constants.LocalServer {

		if err := ipt.NewChain(i.appPacketIPTableContext, uidchain); err != nil {
			return err
		}

		if err := ipt.NewChain(i.appPacketIPTableContext, uidInput); err != nil {
			return err
		}

		// add Trireme-Input and Trireme-Output chains.
		if err := i.addContainerChain(ipt, TriremeOutput, TriremeInput); err != nil {
			return fmt.Errorf("Unable to create trireme input/output chains:%s", err)
		}

		// add NetworkSvc-Input and NetworkSvc-output chains
		if err := i.addContainerChain(ipt, NetworkSvcOutput, NetworkSvcInput); err != nil {
			return fmt.Errorf("Unable to create hostmode input/output chains:%s", err)
		}

		// add HostMode-Input and HostMode-output chains
		if err := i.addContainerChain(ipt, HostModeOutput, HostModeInput); err != nil {
			return fmt.Errorf("Unable to create hostmode input/output chains:%s", err)
		}

	}

	if err := ipt.NewChain(i.appProxyIPTableContext, natProxyInputChain); err != nil {
		return err
	}

	if err := ipt.NewChain(i.appProxyIPTableContext, natProxyOutputChain); err != nil {
		return err
	}

	if err := ipt.NewChain(i.appPacketIPTableContext, proxyOutputChain); err != nil {
		return err
	}

	return ipt.NewChain(i.appPacketIPTableContext, proxyInputChain)
}

// ACLProvider returns the current ACL provider that can be re-used by other entities.
func (i *Instance) ACLProviderV4() provider.IptablesProvider {
	return i.iptV4
}

func (i *Instance) ACLProviderV6() provider.IptablesProvider {
	return i.iptV6
}

// configureContainerRules adds the chain rules for a container.
func (i *Instance) configureContainerRules(ipt provider.IptablesProvider, contextID, appChain, netChain, proxyVIPSet, proxyPortSet string, puInfo *policy.PUInfo) error {

	proxyPort := puInfo.Policy.ServicesListeningPort()

	return i.addChainRules(ipt, contextID, "", appChain, netChain, "", "", "", "", proxyPort, proxyVIPSet, proxyPortSet, "")
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *Instance) configureLinuxRules(ipt provider.IptablesProvider, contextID, appChain, netChain, proxyVIPSet, proxyPortSet string, puInfo *policy.PUInfo) error {

	proxyPort := puInfo.Policy.ServicesListeningPort()

	mark := puInfo.Runtime.Options().CgroupMark

	if mark == "" {
		return errors.New("no mark value found")
	}

	puType := extractors.GetPuType(puInfo.Runtime)

	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(puInfo.Runtime.Options().Services)
	tcpPortSetName := i.getPortSet(contextID)

	if tcpPortSetName == "" {
		return fmt.Errorf("port set was not found for the contextID. This should not happen")
	}

	username := puInfo.Runtime.Options().UserID
	return i.addChainRules(ipt, contextID, tcpPortSetName, appChain, netChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyVIPSet, proxyPortSet, puType)
}

func (i *Instance) deleteProxySets(contextID string) error {
	proxyVIPSetV4, proxyVIPSetV6, proxyPortSet := i.getProxySet(contextID)

	ips := ipset.IPSet{
		Name: proxyVIPSetV4,
	}

	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy", zap.String("SetName", proxyVIPSetV4), zap.Error(err))
	}

	ips = ipset.IPSet{
		Name: proxyVIPSetV6,
	}

	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy", zap.String("SetName", proxyVIPSetV6), zap.Error(err))
	}

	ips = ipset.IPSet{
		Name: proxyPortSet,
	}

	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy", zap.String("set name", proxyPortSet), zap.Error(err))
	}
	return nil
}

type ipsetInfo struct {
	ipsetV4    string
	ipsetV6    string
	ips        map[string]bool
	contextIDs map[string]bool
}

type aclIPset struct {
	ipsetV4   string
	ipsetV6   string
	ports     []string
	protocols []string
	policy    *policy.FlowPolicy
}

func (i *Instance) addToIPset(setname string, data string) error {
	set := i.ipset.GetIpset(setname)

	// ipset can not program this rule
	if data == "0.0.0.0/0" {
		if err := i.addToIPset(setname, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := i.addToIPset(setname, "128.0.0.0/1"); err != nil {
			return err
		}

		return nil
	}

	if data == "::/0" {
		if err := i.addToIPset(setname, "::/1"); err != nil {
			return err
		}

		if err := i.addToIPset(setname, "8000::/1"); err != nil {
			return err
		}
	}

	if err := set.Add(data, 0); err != nil {
		zap.L().Error("unable to insert to ipset "+setname, zap.Error(err))
		return errors.New("Unable to insert ipset")
	}

	return nil
}

func (i *Instance) delFromIPset(setname string, data string) error {
	set := i.ipset.GetIpset(setname)

	if data == "0.0.0.0/0" {
		if err := i.delFromIPset(setname, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := i.delFromIPset(setname, "128.0.0.0/1"); err != nil {
			return err
		}
	}

	if err := set.Del(data); err != nil {
		zap.L().Error("unable to remove from ipset "+setname, zap.Error(err))
		return errors.New("unable to remove from ipset")
	}

	return nil
}

func (i *Instance) removePUFromExternalNetworks(contextID string, serviceID string) {

	info := i.serviceIDToIPsets[serviceID]
	if info == nil {
		return
	}

	delete(info.contextIDs, contextID)

	if len(info.contextIDs) == 0 {
		ips := ipset.IPSet{
			Name: info.ipsetV4,
		}

		if err := ips.Destroy(); err != nil {
			zap.L().Warn("Failed to destroy ipset " + info.ipsetV4)
		}

		ips = ipset.IPSet{
			Name: info.ipsetV6,
		}

		if err := ips.Destroy(); err != nil {
			zap.L().Warn("Failed to destroy ipset " + info.ipsetV6)
		}

		delete(i.serviceIDToIPsets, serviceID)
	}
}

func (i *Instance) destroyACLIPsets(contextID string) {
	for serviceID, info := range i.serviceIDToIPsets {
		if info.contextIDs[contextID] {
			i.removePUFromExternalNetworks(contextID, serviceID)
		}
	}
}

func (i *Instance) synchronizePUACLs(contextID string, appACLs, netACLs policy.IPRuleList) {
	var newPUExternalNetworks []string //nolint

	for _, rule := range appACLs {
		newPUExternalNetworks = append(newPUExternalNetworks, rule.Policy.ServiceID)
	}

	for _, rule := range netACLs {
		newPUExternalNetworks = append(newPUExternalNetworks, rule.Policy.ServiceID)
	}
F1:
	for _, oldServiceID := range i.puToServiceIDs[contextID] {
		for _, newServiceID := range newPUExternalNetworks {
			if newServiceID == oldServiceID {
				continue F1
			}
		}

		i.removePUFromExternalNetworks(contextID, oldServiceID)
	}

	i.puToServiceIDs[contextID] = newPUExternalNetworks
}

func (i *Instance) createACLIPSets(contextID string, rules policy.IPRuleList) ([]aclIPset, error) {
	var info *ipsetInfo

	hashServiceID := func(serviceID string) string {
		hash := murmur3.New64()
		if _, err := io.WriteString(hash, serviceID); err != nil {
			return ""
		}

		return base64.URLEncoding.EncodeToString(hash.Sum(nil))
	}

	acls := make([]aclIPset, len(rules))

	for _, rule := range rules {

		if i.serviceIDToIPsets[rule.Policy.ServiceID] == nil {
			ips := map[string]bool{}

			ipsetNameV4 := puPortSetName(contextID, i.iptV4.GetExtNetSet()+hashServiceID(rule.Policy.ServiceID))
			_, err := i.ipset.NewIpset(ipsetNameV4,
				"hash:net",
				&ipset.Params{})
			if err != nil {
				zap.L().Error("Error creating ipset", zap.Error(err))
				return nil, err
			}

			ipsetNameV6 := puPortSetName(contextID, i.iptV6.GetExtNetSet()+hashServiceID(rule.Policy.ServiceID))
			_, err = i.ipset.NewIpset(ipsetNameV6,
				"hash:net",
				&ipset.Params{HashFamily: "inet6"})
			if err != nil {
				zap.L().Error("Error creating ipset", zap.Error(err))
				return nil, err
			}

			for _, address := range rule.Addresses {
				ip, _, err := net.ParseCIDR(address)

				if err != nil {
					zap.L().Error("Incorrect address ", zap.String("address", address))
					continue
				}

				if ip.To4() != nil {
					if err := i.addToIPset(ipsetNameV4, address); err != nil {
						return nil, err
					}
				} else {
					if err := i.addToIPset(ipsetNameV6, address); err != nil {
						return nil, err
					}
				}
				ips[address] = true
			}

			mapCID := map[string]bool{}
			mapCID[contextID] = true

			info = &ipsetInfo{ipsetV4: ipsetNameV4,
				ipsetV6:    ipsetNameV6,
				ips:        ips,
				contextIDs: mapCID,
			}

			i.serviceIDToIPsets[rule.Policy.ServiceID] = info
		} else {
			info = i.serviceIDToIPsets[rule.Policy.ServiceID]
			newips := map[string]bool{}

			for _, address := range rule.Addresses {

				// add new entries
				if !info.ips[address] {
					ip, _, _ := net.ParseCIDR(address) //nolint

					if ip.To4() != nil {
						if err := i.addToIPset(info.ipsetV4, address); err != nil {
							return nil, err
						}
					} else {
						if err := i.addToIPset(info.ipsetV6, address); err != nil {
							return nil, err
						}
					}
					newips[address] = true
				} else {
					newips[address] = true
					info.ips[address] = false
				}
			}
			// Remove the old entries
			for address, val := range info.ips {
				if val {
					ip, _, _ := net.ParseCIDR(address)

					if ip.To4() != nil {
						if err := i.delFromIPset(info.ipsetV4, address); err != nil {
							return nil, err
						}
					} else {
						if err := i.delFromIPset(info.ipsetV6, address); err != nil {
							return nil, err
						}
					}
				}
			}

			info.ips = newips
			info.contextIDs[contextID] = true
		}

		acls = append(acls, aclIPset{
			ipsetV4:   info.ipsetV4,
			ipsetV6:   info.ipsetV6,
			ports:     rule.Ports,
			protocols: rule.Protocols,
			policy:    rule.Policy,
		})
	}

	return acls, nil
}

// Install rules will install all the rules and update the port sets.
func (i *Instance) installRules(ipt provider.IptablesProvider, contextID, appChain, netChain, proxyVIPSet, proxyPortSet string, containerInfo *policy.PUInfo, appACLIPset, netACLIPset []aclIPset) error {
	policyrules := containerInfo.Policy

	// Install the PU specific chain first.
	if err := i.addContainerChain(ipt, appChain, netChain); err != nil {
		return err
	}

	// If its a remote and thus container, configure container rules.
	if i.mode == constants.RemoteContainer || i.mode == constants.Sidecar {
		if err := i.configureContainerRules(ipt, contextID, appChain, netChain, proxyVIPSet, proxyPortSet, containerInfo); err != nil {
			return err
		}
	}

	// If its a Linux process configure the Linux rules.
	if i.mode == constants.LocalServer {
		if err := i.configureLinuxRules(ipt, contextID, appChain, netChain, proxyVIPSet, proxyPortSet, containerInfo); err != nil {
			return err
		}
	}

	isHostPU := extractors.IsHostPU(containerInfo.Runtime, i.mode)

	if err := i.addPacketTrap(ipt, appChain, netChain, isHostPU); err != nil {
		return err
	}

	if err := i.addAppACLs(ipt, contextID, appChain, netChain, appACLIPset); err != nil {
		return err
	}

	if err := i.addNetACLs(ipt, contextID, appChain, netChain, netACLIPset); err != nil {
		return err
	}

	if i.isLegacyKernel {
		// doesn't work for clients.
		tcpPorts, _ := common.ConvertServicesToProtocolPortList(containerInfo.Runtime.Options().Services)
		if err := i.addLegacyNATExclusionACLs(contextID, containerInfo.Runtime.Options().CgroupMark, policyrules.ExcludedNetworks(), tcpPorts); err != nil {
			return err
		}

	} else {
		if err := i.addNATExclusionACLs(contextID, containerInfo.Runtime.Options().CgroupMark, policyrules.ExcludedNetworks()); err != nil {
			return err
		}
	}
	return i.addExclusionACLs(appChain, netChain, policyrules.ExcludedNetworks())
}

// puPortSetName returns the name of the pu portset.
func puPortSetName(contextID string, prefix string) string {
	hash := murmur3.New64()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return ""
	}

	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	if len(contextID) > 4 {
		contextID = contextID[:4] + output[:4]
	} else {
		contextID = contextID + output[:4]
	}

	if len(prefix) > 16 {
		prefix = prefix[:16]
	}

	return (prefix + contextID)
}
