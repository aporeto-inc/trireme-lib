package iptablesctrl

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	targetNetworkSet         = "TargetNetSet"
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
	ipt                     provider.IptablesProvider
	ipset                   provider.IpsetProvider
	targetSet               provider.Ipset
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

	ipt, err := provider.NewGoIPTablesProvider([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	ips := provider.NewGoIPsetProvider()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ipsets: %s", err)
	}

	i := &Instance{
		fqc:                     fqc,
		ipt:                     ipt,
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

// ConfigureRules implments the ConfigureRules interface. It will create the
// port sets and then it will call install rules to create all the ACLs for
// the given chains. PortSets are only created here. Updates will use the
// exact same logic.
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	proxySetName := puPortSetName(contextID, proxyPortSetPrefix)

	// Create the proxy sets.
	if err := i.createProxySets(proxySetName); err != nil {
		return err
	}

	if err := i.createPortSet(contextID, containerInfo); err != nil {
		return err
	}

	// Install all the rules
	if err := i.installRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
		return err
	}

	return i.ipt.Commit()
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, puType string, exclusions []string) error {

	proxyPortSetName := puPortSetName(contextID, proxyPortSetPrefix)
	tcpPortSetName := i.getPortSet(contextID)

	if tcpPortSetName == "" {
		zap.L().Error("port set name can not be nil")
	}

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		// Don't return here we can still try and reclaims portset and targetnetwork sets
		zap.L().Error("Count not generate chain name", zap.Error(err))
	}

	if err := i.deleteChainRules(contextID, tcpPortSetName, appChain, netChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyPortSetName, puType); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	// if i.isLegacyKernel {
	// 	if err = i.deleteLegacyNATExclusionACLs(mark, proxyPortSetName, exclusions, tcpPorts); err != nil {
	// 		zap.L().Warn("Failed to clean up legacy NAT exclusions", zap.Error(err))
	// 	}

	// } else {
	// 	if err = i.deleteNATExclusionACLs(mark, proxyPortSetName, exclusions); err != nil {
	// 		zap.L().Warn("Failed to clean up NAT exclusions", zap.Error(err))
	// 	}
	// }

	if err = i.deleteAllContainerChains(appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	if err := i.ipt.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	if err := i.deletePortSet(contextID); err != nil {
		zap.L().Warn("Failed to remove port set")
	}

	if err := i.deleteProxySets(proxyPortSetName); err != nil {
		zap.L().Warn("Failed to delete proxy sets", zap.Error(err))
	}

	i.destroyACLIPsets(contextID)

	return nil
}

// UpdateRules implements the update part of the interface. Update will call
// installrules to install the new rules and then it will delete the old rules.
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {

	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}

	proxyPort := containerInfo.Policy.ServicesListeningPort()
	proxySetName := puPortSetName(contextID, proxyPortSetPrefix)

	portSetName := i.getPortSet(contextID)
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
	// Install the new rules
	if err := i.installRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
		return nil
	}

	// Remove mapping from old chain
	if i.mode != constants.LocalServer {
		if err := i.deleteChainRules(contextID, portSetName, oldAppChain, oldNetChain, "", "", "", "", proxyPort, proxySetName, puType); err != nil {
			return err
		}
	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		username := containerInfo.Runtime.Options().UserID

		if err := i.deleteChainRules(contextID, portSetName, oldAppChain, oldNetChain, tcpPorts, udpPorts, mark, username, proxyPort, proxySetName, puType); err != nil {
			return err
		}
	}

	// mark := ""
	// if containerInfo.Runtime != nil {
	// 	mark = containerInfo.Runtime.Options().CgroupMark
	// }

	// excludedNetworks := []string{}
	// if oldContainerInfo != nil && oldContainerInfo.Policy != nil {
	// 	excludedNetworks = oldContainerInfo.Policy.ExcludedNetworks()
	// }

	// if i.isLegacyKernel {
	// 	if err := i.deleteLegacyNATExclusionACLs(mark, proxySetName, excludedNetworks, tcpPorts); err != nil {
	// 		zap.L().Warn("Failed to clean up legacy NAT exclusions", zap.Error(err))
	// 	}

	// } else {
	// 	if err := i.deleteNATExclusionACLs(mark, proxySetName, excludedNetworks); err != nil {
	// 		zap.L().Warn("Failed to clean up NAT exclusions", zap.Error(err))
	// 	}
	// }

	// // Delete the old chain to clean up
	if err := i.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		return err
	}

	if err = i.ipt.Commit(); err != nil {
		return err
	}

	i.synchronizePUACLs(contextID, policyrules.ApplicationACLs(), policyrules.NetworkACLs())

	return nil
}

// Run starts the iptables controller
func (i *Instance) Run(ctx context.Context) error {

	// Clean any previous ACLs
	if err := i.cleanACLs(); err != nil {
		zap.L().Warn("Unable to clean previous acls while starting the supervisor", zap.Error(err))
	}

	if err := i.InitializeChains(); err != nil {
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

	if err := i.cleanACLs(); err != nil {
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
	if len(current) > 0 && i.targetSet != nil {
		return i.updateTargetNetworks(current, networks)
	}

	// Create the target network set
	if err := i.createTargetSet(networks); err != nil {
		return err
	}

	// Insert the ACLS that point to the target networks
	if err := i.setGlobalRules(i.appPacketIPTableSection, i.netPacketIPTableSection); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	return nil
}

// InitializeChains initializes the chains.
func (i *Instance) InitializeChains() error {

	if i.mode == constants.LocalServer {

		if err := i.ipt.NewChain(i.appPacketIPTableContext, uidchain); err != nil {
			return err
		}

		if err := i.ipt.NewChain(i.appPacketIPTableContext, uidInput); err != nil {
			return err
		}

		// add Trireme-Input and Trireme-Output chains.
		if err := i.addContainerChain(TriremeOutput, TriremeInput); err != nil {
			return fmt.Errorf("Unable to create trireme input/output chains:%s", err)
		}

		// add NetworkSvc-Input and NetworkSvc-output chains
		if err := i.addContainerChain(NetworkSvcOutput, NetworkSvcInput); err != nil {
			return fmt.Errorf("Unable to create hostmode input/output chains:%s", err)
		}

		// add HostMode-Input and HostMode-output chains
		if err := i.addContainerChain(HostModeOutput, HostModeInput); err != nil {
			return fmt.Errorf("Unable to create hostmode input/output chains:%s", err)
		}

	}

	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyInputChain); err != nil {
		return err
	}

	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyOutputChain); err != nil {
		return err
	}

	if err := i.ipt.NewChain(i.appPacketIPTableContext, proxyOutputChain); err != nil {
		return err
	}

	return i.ipt.NewChain(i.appPacketIPTableContext, proxyInputChain)
}

// ACLProvider returns the current ACL provider that can be re-used by other entities.
func (i *Instance) ACLProvider() provider.IptablesProvider {
	return i.ipt
}

// configureContainerRules adds the chain rules for a container.
func (i *Instance) configureContainerRules(contextID, appChain, netChain, proxyPortSetName string, puInfo *policy.PUInfo) error {

	proxyPort := puInfo.Policy.ServicesListeningPort()

	return i.addChainRules(contextID, "", appChain, netChain, "", "", "", "", proxyPort, proxyPortSetName, "")
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *Instance) configureLinuxRules(contextID, appChain, netChain, proxyPortSetName string, puInfo *policy.PUInfo) error {

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
	return i.addChainRules(contextID, tcpPortSetName, appChain, netChain, tcpPorts, udpPorts, mark, username, proxyPort, proxyPortSetName, puType)
}

func (i *Instance) deleteProxySets(proxyPortSetName string) error {
	dstPortSetName, srvPortSetName := i.getSetNames(proxyPortSetName)
	ips := ipset.IPSet{
		Name: dstPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", dstPortSetName), zap.Error(err))
	}
	ips = ipset.IPSet{
		Name: srvPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear proxy port set", zap.String("set name", srvPortSetName), zap.Error(err))
	}
	return nil
}

type ipsetInfo struct {
	ipset      string
	ips        map[string]bool
	contextIDs map[string]bool
}

type aclIPset struct {
	ipset     string
	ports     []string
	protocols []string
	policy    *policy.FlowPolicy
}

func (i *Instance) addToIPset(setname string, data string) error {
	set := i.ipset.GetIpset(setname)

	// ipset can not program this rule
	if data == "0.0.0.0/0" {
		if err := i.addToIPset(setname, "::/1"); err != nil {
			return err
		}

		if err := i.addToIPset(setname, "8000::/1"); err != nil {
			return err
		}

		return nil
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
			Name: info.ipset,
		}

		if err := ips.Destroy(); err != nil {
			zap.L().Warn("Failed to destroy ipset " + info.ipset)
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

			ipsetName := puPortSetName(contextID, "_extnet_"+hashServiceID(rule.Policy.ServiceID))
			_, err := i.ipset.NewIpset(ipsetName,
				"hash:net",
				&ipset.Params{HashFamily: "inet6"})
			if err != nil {
				zap.L().Error("Error creating ipset", zap.Error(err))
				return nil, err
			}

			for _, address := range rule.Addresses {
				if err := i.addToIPset(ipsetName, address); err != nil {
					return nil, err
				}
				ips[address] = true
			}

			mapCID := map[string]bool{}
			mapCID[contextID] = true

			info = &ipsetInfo{ipset: ipsetName,
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
					if err := i.addToIPset(info.ipset, address); err != nil {
						return nil, err
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
					if err := i.delFromIPset(info.ipset, address); err != nil {
						return nil, err
					}
				}
			}

			info.ips = newips
			info.contextIDs[contextID] = true
		}

		acls = append(acls, aclIPset{
			ipset:     info.ipset,
			ports:     rule.Ports,
			protocols: rule.Protocols,
			policy:    rule.Policy,
		})
	}

	return acls, nil
}

// Install rules will install all the rules and update the port sets.
func (i *Instance) installRules(contextID, appChain, netChain, proxySetName string, containerInfo *policy.PUInfo) error {
	var err error
	var appACLIPset, netACLIPset []aclIPset
	policyrules := containerInfo.Policy

	if err := i.updateProxySet(containerInfo.Policy, proxySetName); err != nil {
		return err
	}

	if appACLIPset, err = i.createACLIPSets(contextID, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if netACLIPset, err = i.createACLIPSets(contextID, policyrules.NetworkACLs()); err != nil {
		return err
	}

	// Install the PU specific chain first.
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	// If its a remote and thus container, configure container rules.
	if i.mode == constants.RemoteContainer || i.mode == constants.Sidecar {
		if err := i.configureContainerRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
			return err
		}
	}

	// If its a Linux process configure the Linux rules.
	if i.mode == constants.LocalServer {
		if err := i.configureLinuxRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
			return err
		}
	}

	isHostPU := extractors.IsHostPU(containerInfo.Runtime, i.mode)

	if err := i.addPacketTrap(appChain, netChain, isHostPU); err != nil {
		return err
	}

	if err := i.addAppACLs(contextID, appChain, netChain, appACLIPset); err != nil {
		return err
	}

	if err := i.addNetACLs(contextID, appChain, netChain, netACLIPset); err != nil {
		return err
	}

	if i.isLegacyKernel {
		// doesn't work for clients.
		tcpPorts, _ := common.ConvertServicesToProtocolPortList(containerInfo.Runtime.Options().Services)
		if err := i.addLegacyNATExclusionACLs(containerInfo.Runtime.Options().CgroupMark, proxySetName, policyrules.ExcludedNetworks(), tcpPorts); err != nil {
			return err
		}

	} else {
		if err := i.addNATExclusionACLs(containerInfo.Runtime.Options().CgroupMark, proxySetName, policyrules.ExcludedNetworks()); err != nil {
			return err
		}
	}
	return nil
	//i.addExclusionACLs(appChain, netChain, policyrules.ExcludedNetworks())
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
