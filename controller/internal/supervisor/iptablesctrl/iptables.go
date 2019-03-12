package iptablesctrl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"text/template"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

const (
	chainPrefix          = "TRI-"
	mainAppChain         = chainPrefix + "App"
	mainNetChain         = chainPrefix + "Net"
	uidchain             = chainPrefix + "UID-Net"
	uidInput             = chainPrefix + "UID-App"
	appChainPrefix       = chainPrefix + "App-"
	netChainPrefix       = chainPrefix + "Net-"
	targetTCPNetworkSet  = chainPrefix + "TargetTCP"
	targetUDPNetworkSet  = chainPrefix + "TargetUDP"
	excludedNetworkSet   = chainPrefix + "Excluded"
	uidPortSetPrefix     = chainPrefix + "U-Port-"
	processPortSetPrefix = chainPrefix + "ProcPort-"
	natProxyOutputChain  = chainPrefix + "Redir-App"
	natProxyInputChain   = chainPrefix + "Redir-Net"
	proxyOutputChain     = chainPrefix + "Prx-App"
	proxyInputChain      = chainPrefix + "Prx-Net"
	proxyPortSetPrefix   = chainPrefix + "Proxy-"

	// TriremeInput represent the chain that contains pu input rules.
	TriremeInput = chainPrefix + "Pid-Net"
	// TriremeOutput represent the chain that contains pu output rules.
	TriremeOutput = chainPrefix + "Pid-App"

	// NetworkSvcInput represent the chain that contains NetworkSvc input rules.
	NetworkSvcInput = chainPrefix + "Svc-Net"

	// NetworkSvcOutput represent the chain that contains NetworkSvc output rules.
	NetworkSvcOutput = chainPrefix + "Svc-App"

	// HostModeInput represent the chain that contains Hostmode input rules.
	HostModeInput = chainPrefix + "Hst-Net"

	// HostModeOutput represent the chain that contains Hostmode output rules.
	HostModeOutput = chainPrefix + "Hst-App"

	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionInput      = "INPUT"
	ipTableSectionPreRouting = "PREROUTING"
	proxyMark                = "0x40"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	fqc                     *fqconfig.FilterQueue
	ipt                     provider.IptablesProvider
	ipset                   provider.IpsetProvider
	targetTCPSet            provider.Ipset
	targetUDPSet            provider.Ipset
	excludedNetworksSet     provider.Ipset
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
	cfg                     *runtime.Configuration
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
func NewInstance(fqc *fqconfig.FilterQueue, mode constants.ModeType, cfg *runtime.Configuration) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	ips := provider.NewGoIPsetProvider()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ipsets: %s", err)
	}

	targetTCPSet, err := ips.NewIpset(targetTCPNetworkSet, "hash:net", &ipset.Params{})
	if err != nil {
		return nil, fmt.Errorf("unable to create ipset for %s: %s", targetUDPNetworkSet, err)
	}

	targetUDPSet, err := ips.NewIpset(targetUDPNetworkSet, "hash:net", &ipset.Params{})
	if err != nil {
		return nil, fmt.Errorf("unable to create ipset for %s: %s", targetUDPNetworkSet, err)
	}

	excludedNetworkSet, err := ips.NewIpset(excludedNetworkSet, "hash:net", &ipset.Params{})
	if err != nil {
		return nil, fmt.Errorf("unable to create ipset for %s: %s", excludedNetworkSet, err)
	}

	i := &Instance{
		fqc:                     fqc,
		ipt:                     ipt,
		ipset:                   ips,
		targetTCPSet:            targetTCPSet,
		targetUDPSet:            targetUDPSet,
		excludedNetworksSet:     excludedNetworkSet,
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

	if err := i.SetTargetNetworks(cfg); err != nil {
		return nil, fmt.Errorf("unable to initialize target networks: %s", err)
	}

	lock.Lock()
	instance = i
	defer lock.Unlock()

	return i, nil
}

// ConfigureRules implments the ConfigureRules interface. It will create the
// port sets and then it will call install rules to create all the ACLs for
// the given chains. PortSets are only created here. Updates will use the
// exact same logic.
func (i *Instance) ConfigureRules(version int, contextID string, pu *policy.PUInfo) error {

	if err := i.createPortSet(contextID, pu); err != nil {
		return err
	}

	cfg, err := i.newACLInfo(version, contextID, pu, extractors.GetPuType(pu.Runtime))
	if err != nil {
		return err
	}

	// Create the proxy sets.
	if err := i.createProxySets(cfg.ProxySetName); err != nil {
		return err
	}

	// Install all the rules
	if err := i.installRules(cfg, pu); err != nil {
		return err
	}

	return i.ipt.Commit()
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, puType string) error {

	cfg, err := i.newACLInfo(version, contextID, nil, puType)
	if err != nil {
		zap.L().Error("unable to create cleanup configuration", zap.Error(err))
		return err
	}

	cfg.UDPPorts = udpPorts
	cfg.TCPPorts = tcpPorts
	cfg.CgroupMark = mark
	cfg.Mark = mark
	cfg.UID = username
	cfg.PUType = puType
	cfg.ProxyPort = proxyPort

	if err := i.deleteChainRules(cfg); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	if err = i.deleteAllContainerChains(cfg.AppChain, cfg.NetChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	if err := i.ipt.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	if err := i.deletePortSet(contextID); err != nil {
		zap.L().Warn("Failed to remove port set")
	}

	if err := i.deleteProxySets(cfg.ProxySetName); err != nil {
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

	newCfg, err := i.newACLInfo(version, contextID, containerInfo, "")
	if err != nil {
		return err
	}

	oldCfg, err := i.newACLInfo(version^1, contextID, oldContainerInfo, "")
	if err != nil {
		return err
	}

	// Install the new rules
	if err := i.installRules(newCfg, containerInfo); err != nil {
		return nil
	}

	// Remove mapping from old chain
	if err := i.deleteChainRules(oldCfg); err != nil {
		return err
	}

	// Delete the old chain to clean up
	if err := i.deleteAllContainerChains(oldCfg.AppChain, oldCfg.NetChain); err != nil {
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

	// Initialize all the global Trireme chains
	if err := i.initializeChains(); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	// Insert the global ACLS.
	if err := i.setGlobalRules(); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
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
func (i *Instance) SetTargetNetworks(c *runtime.Configuration) error {

	if c == nil {
		return nil
	}

	cfg := c.DeepCopy()

	var oldConfig *runtime.Configuration
	if i.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.cfg.DeepCopy()
	}

	// If there are no target networks, capture all traffic
	if len(cfg.TCPTargetNetworks) == 0 {
		cfg.TCPTargetNetworks = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}

	// Cleanup old ACLs
	if err := i.updateTargetNetworks(i.targetTCPSet, oldConfig.TCPTargetNetworks, cfg.TCPTargetNetworks); err != nil {
		return err
	}

	if err := i.updateTargetNetworks(i.targetUDPSet, oldConfig.UDPTargetNetworks, cfg.UDPTargetNetworks); err != nil {
		return err
	}

	if err := i.updateTargetNetworks(i.excludedNetworksSet, oldConfig.ExcludedNetworks, cfg.ExcludedNetworks); err != nil {
		return err
	}

	i.cfg = cfg

	return nil
}

// InitializeChains initializes the chains.
func (i *Instance) initializeChains() error {

	cfg, err := i.newACLInfo(0, "", nil, "")
	if err != nil {
		return err
	}

	tmpl := template.Must(template.New(triremChains).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(triremChains))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	for _, rule := range rules {
		if len(rule) != 4 {
			continue
		}
		if err := i.ipt.NewChain(rule[1], rule[3]); err != nil {
			return err
		}
	}

	return nil
}

// ACLProvider returns the current ACL provider that can be re-used by other entities.
func (i *Instance) ACLProvider() provider.IptablesProvider {
	return i.ipt
}

// configureContainerRules adds the chain rules for a container.
func (i *Instance) configureContainerRules(cfg *ACLInfo) error {

	return i.addChainRules(cfg)
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *Instance) configureLinuxRules(cfg *ACLInfo) error {

	if cfg.CgroupMark == "" {
		return errors.New("no mark value found")
	}

	if cfg.TCPPortSet == "" {
		return fmt.Errorf("port set was not found for the contextID. This should not happen")
	}

	return i.addChainRules(cfg)
}

func (i *Instance) deleteProxySets(proxyPortSetName string) error { // nolint
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

func (i *Instance) addToIPset(set provider.Ipset, data string) error {

	// ipset can not program this rule
	if data == "0.0.0.0/0" {
		if err := i.addToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := i.addToIPset(set, "128.0.0.0/1"); err != nil {
			return err
		}

		return nil
	}

	return set.Add(data, 0)
}

func (i *Instance) delFromIPset(set provider.Ipset, data string) error {

	if data == "0.0.0.0/0" {
		if err := i.delFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := i.delFromIPset(set, "128.0.0.0/1"); err != nil {
			return err
		}
	}

	return set.Del(data)
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
			set, err := i.ipset.NewIpset(ipsetName,
				"hash:net",
				&ipset.Params{})
			if err != nil {
				zap.L().Error("Error creating ipset", zap.Error(err))
				return nil, err
			}

			for _, address := range rule.Addresses {
				if err := i.addToIPset(set, address); err != nil {
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
					if err := i.addToIPset(i.ipset.GetIpset(info.ipset), address); err != nil {
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
					if err := i.delFromIPset(i.ipset.GetIpset(info.ipset), address); err != nil {
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
func (i *Instance) installRules(cfg *ACLInfo, containerInfo *policy.PUInfo) error {
	var err error
	var appACLIPset, netACLIPset []aclIPset
	policyrules := containerInfo.Policy

	if err := i.updateProxySet(containerInfo.Policy, cfg.ProxySetName); err != nil {
		return err
	}

	if appACLIPset, err = i.createACLIPSets(cfg.ContextID, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if netACLIPset, err = i.createACLIPSets(cfg.ContextID, policyrules.NetworkACLs()); err != nil {
		return err
	}

	// Install the PU specific chain first.
	if err := i.addContainerChain(cfg.AppChain, cfg.NetChain); err != nil {
		return err
	}

	// If its a remote and thus container, configure container rules.
	if i.mode == constants.RemoteContainer || i.mode == constants.Sidecar {
		if err := i.configureContainerRules(cfg); err != nil {
			return err
		}
	}

	// If its a Linux process configure the Linux rules.
	if i.mode == constants.LocalServer {
		if err := i.configureLinuxRules(cfg); err != nil {
			return err
		}
	}

	isHostPU := extractors.IsHostPU(containerInfo.Runtime, i.mode)

	if err := i.addNetACLs(cfg.ContextID, cfg.AppChain, cfg.NetChain, netACLIPset); err != nil {
		return err
	}

	if err := i.addAppACLs(cfg.ContextID, cfg.AppChain, cfg.NetChain, appACLIPset); err != nil {
		return err
	}

	if err := i.addPacketTrap(cfg, isHostPU); err != nil {
		return err
	}

	return nil
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
