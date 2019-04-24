package iptablesctrl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"text/template"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/common"
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
	chainPrefix         = "TRI-"
	mainAppChain        = chainPrefix + "App"
	mainNetChain        = chainPrefix + "Net"
	uidchain            = chainPrefix + "UID-App"
	uidInput            = chainPrefix + "UID-Net"
	appChainPrefix      = chainPrefix + "App-"
	netChainPrefix      = chainPrefix + "Net-"
	natProxyOutputChain = chainPrefix + "Redir-App"
	natProxyInputChain  = chainPrefix + "Redir-Net"
	proxyOutputChain    = chainPrefix + "Prx-App"
	proxyInputChain     = chainPrefix + "Prx-Net"

	targetTCPNetworkSet  = "TargetTCP"
	targetUDPNetworkSet  = "TargetUDP"
	excludedNetworkSet   = "Excluded"
	uidPortSetPrefix     = "UID-Port-"
	processPortSetPrefix = "ProcPort-"
	proxyPortSetPrefix   = "Proxy-"
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
	appPacketIPTableContext  = "mangle"
	netPacketIPTableContext  = "mangle"
	appProxyIPTableContext   = "nat"

	proxyMark = "0x40"
)

type iptables struct {
	impl                  ipImpl
	fqc                   *fqconfig.FilterQueue
	mode                  constants.ModeType
	createPUPortSet       func(string) error
	isLegacyKernel        bool
	conntrackCmd          func([]string)
	ipset                 provider.IpsetProvider
	targetTCPSet          provider.Ipset
	targetUDPSet          provider.Ipset
	excludedNetworksSet   provider.Ipset
	cfg                   *runtime.Configuration
	contextIDToPortSetMap cache.DataStore
	serviceIDToIPsets     map[string]*ipsetInfo
	puToServiceIDs        map[string][]string
}

//Instance is the structure holding the ipv4 and ipv6 handles
type Instance struct {
	iptv4 *iptables
	iptv6 *iptables
}

var instance *Instance
var lock sync.RWMutex

// GetInstance returns the instance of the iptables object.
func GetInstance() *Instance {
	lock.Lock()
	defer lock.Unlock()
	return instance
}

type ipImpl interface {
	provider.IptablesProvider
	GetIPSetPrefix() string
	GetIPSetParam() *ipset.Params
	ProtocolAllowed(proto string) bool
	IPFilter() func(net.IP) bool
	GetDefaultIP() string
	NeedICMP() bool
}

type ipFilter func(net.IP) bool

func filterNetworks(c *runtime.Configuration, filter ipFilter) *runtime.Configuration {
	filterIPs := func(ips []string) []string {
		var filteredIPs []string

		for _, ip := range ips {
			netIP := net.ParseIP(ip)
			if netIP == nil {
				netIP, _, _ = net.ParseCIDR(ip)
			}

			if filter(netIP) {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	return &runtime.Configuration{
		TCPTargetNetworks: filterIPs(c.TCPTargetNetworks),
		UDPTargetNetworks: filterIPs(c.UDPTargetNetworks),
		ExcludedNetworks:  filterIPs(c.ExcludedNetworks),
	}
}

func createIPInstance(impl ipImpl, ips provider.IpsetProvider, fqc *fqconfig.FilterQueue, mode constants.ModeType) (*iptables, error) {

	// Create all the basic target sets. These are the global target sets
	// that do not depend on policy configuration. If they already exist
	// we will delete them and start again.

	targetTCPSet, targetUDPSet, excludedSet, err := createGlobalSets(impl.GetIPSetPrefix(), ips, impl.GetIPSetParam())
	if err != nil {
		return nil, fmt.Errorf("unable to create global sets: %s", err)
	}

	return &iptables{
		impl:                  impl,
		fqc:                   fqc,
		mode:                  mode,
		ipset:                 ips,
		createPUPortSet:       ipsetCreatePortset,
		isLegacyKernel:        buildflags.IsLegacyKernel(),
		conntrackCmd:          flushUDPConntrack,
		targetTCPSet:          targetTCPSet,
		targetUDPSet:          targetUDPSet,
		excludedNetworksSet:   excludedSet,
		cfg:                   nil,
		contextIDToPortSetMap: cache.NewCache("contextIDToPortSetMap"),
		serviceIDToIPsets:     map[string]*ipsetInfo{},
		puToServiceIDs:        map[string][]string{},
	}, nil
}

// NewInstance creates a new iptables controller instance
func NewInstance(fqc *fqconfig.FilterQueue, mode constants.ModeType) (*Instance, error) {

	ips := provider.NewGoIPsetProvider()

	ipv4Impl, err := GetIPv4Impl()
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 instance: %s", err)
	}

	iptInstanceV4, err := createIPInstance(ipv4Impl, ips, fqc, mode)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 instance: %s", err)
	}

	ipv6Impl, err := GetIPv6Impl()
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 instance: %s", err)
	}

	iptInstanceV6, err := createIPInstance(ipv6Impl, ips, fqc, mode)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 instance: %s", err)
	}

	return newInstanceWithProviders(iptInstanceV4, iptInstanceV6)
}

// newInstanceWithProviders is called after ipt and ips have been created. This helps
// with all the unit testing to be able to mock the providers.
func newInstanceWithProviders(iptv4 *iptables, iptv6 *iptables) (*Instance, error) {

	i := &Instance{
		iptv4: iptv4,
		iptv6: iptv6,
	}

	lock.Lock()
	instance = i
	defer lock.Unlock()

	return i, nil
}

func (i *iptables) SetTargetNetworks(c *runtime.Configuration) error {
	if c == nil {
		return nil
	}

	// If there are no target networks, capture all traffic
	if len(c.TCPTargetNetworks) == 0 {
		c.TCPTargetNetworks = []string{"0.0.0.0/0", "::/0"}
	}
	cfg := filterNetworks(c, i.impl.IPFilter())
	var oldConfig *runtime.Configuration

	if i.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.cfg.DeepCopy()
	}

	if err := i.updateAllTargetNetworks(cfg, oldConfig); err != nil {
		return err
	}

	i.cfg = cfg
	return nil
}

func (i *iptables) Run(ctx context.Context) error {

	go func() {
		<-ctx.Done()
		zap.L().Debug("Cleaning the iptable rules")

		i.CleanUp() // nolint
	}()

	// Clean any previous ACLs. This is needed in case we crashed at some
	// earlier point or there are other ACLs that create conflicts. We
	// try to clean only ACLs related to Trireme.
	if err := i.cleanACLs(); err != nil {
		return fmt.Errorf("Unable to clean previous acls while starting the supervisor: %s", err)
	}

	// Initialize all the global Trireme chains. There are several global chaims
	// that apply to all PUs:
	// Tri-App/Tri-Net are the main chains for the egress/ingress directions
	// UID related chains for any UID PUs.
	// Host, Service, Pid chains for the different modes of operation (host mode, pu mode, host service).
	// The priority is explicit (Pid activations take precedence of Service activations and Host Services)
	if err := i.initializeChains(); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	// Insert the global ACLS. These are the main ACLs that will direct traffic from
	// the INPUT/OUTPUT chains to the Trireme chains. They also includes the main
	// rules of the main chains. These rules are never touched again, unless
	// if we gracefully terminate.
	if err := i.setGlobalRules(); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	return nil
}

// ConfigureRules implments the ConfigureRules interface. It will create the
// port sets and then it will call install rules to create all the ACLs for
// the given chains. PortSets are only created here. Updates will use the
// exact same logic.
func (i *iptables) ConfigureRules(version int, contextID string, pu *policy.PUInfo) error {

	var err error
	var cfg *ACLInfo

	// First we create an IPSet for destination matching ports. This only
	// applies to Linux type PUs. A port set is associated with every PU,
	// and packets matching this destination get associated with the context
	// of the PU.
	if err = i.createPortSet(contextID, pu.Runtime.Options().UserID); err != nil {
		return err
	}

	// We create the generic ACL object that is used for all the templates.
	cfg, err = i.newACLInfo(version, contextID, pu, pu.Runtime.PUType())
	if err != nil {
		return err
	}

	// Create the proxy sets. These are the target sets that will match
	// traffic towards the L4 and L4 services. There are two sets created
	// for every PU in this context (for outgoing and incoming traffic).
	// The outgoing sets capture all traffic towards specific destinations
	// as proxied traffic. Incoming sets correspond to the listening
	// services.
	if err = i.createProxySets(cfg.ProxySetName); err != nil {
		return err
	}

	// At this point we can install all the ACL rules that will direct
	// traffic to user space, allow for external access or direct
	// traffic towards the proxies
	if err = i.installRules(cfg, pu); err != nil {
		return err
	}

	// We commit the ACLs at the end. Note, that some of the ACLs in the
	// NAT table are not committed as a group. The commit function only
	// applies when newer versions of tables are installed (1.6.2 and above).
	if err = i.impl.Commit(); err != nil {
		zap.L().Error("unable to configure rules", zap.Error(err))
		return err
	}

	i.conntrackCmd(i.cfg.UDPTargetNetworks)
	return nil
}

func (i *iptables) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, puType common.PUType) error {
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

	// We clean up the chain rules first, so that we can delete the chains.
	// If any rule is not deleted, then the chain will show as busy.
	if err := i.deleteChainRules(cfg); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	// We can now delete the chains we have created for this PU. Note that
	// in every case we only create two chains for every PU. All other
	// chains are global.
	if err = i.deletePUChains(cfg.AppChain, cfg.NetChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	// We call commit to update all the changes, before destroying the ipsets.
	// References must be deleted for ipset deletion to succeed.
	if err := i.impl.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	// We delete the set that captures all destination ports of the
	// PU. This only holds for Linux PUs.
	if err := i.deletePortSet(contextID); err != nil {
		zap.L().Warn("Failed to remove port set")
	}

	// We delete the proxy port sets that were created for this PU.
	if err := i.deleteProxySets(cfg.ProxySetName); err != nil {
		zap.L().Warn("Failed to delete proxy sets", zap.Error(err))
	}

	// Destroy all the ACL related IPSets that were created
	// on demand for any external services.
	i.destroyACLIPsets(contextID)

	return nil
}

func (i *iptables) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}

	// We cache the old config and we use it to delete the previous
	// rules. Every time we update the policy the version changes to
	// its binary complement.
	newCfg, err := i.newACLInfo(version, contextID, containerInfo, containerInfo.Runtime.PUType())
	if err != nil {
		return err
	}

	oldCfg, err := i.newACLInfo(version^1, contextID, oldContainerInfo, containerInfo.Runtime.PUType())
	if err != nil {
		return err
	}

	// Install all the new rules. The hooks to the new chains are appended
	// and do not take effect yet.
	if err := i.installRules(newCfg, containerInfo); err != nil {
		return nil
	}

	// Remove mapping from old chain. By removing the old hooks the new
	// hooks take priority.
	if err := i.deleteChainRules(oldCfg); err != nil {
		return err
	}

	// Delete the old chains, since there are not references any more.
	if err := i.deletePUChains(oldCfg.AppChain, oldCfg.NetChain); err != nil {
		return err
	}

	// Commit all actions in on iptables-restore function.
	if err := i.impl.Commit(); err != nil {
		return err
	}

	// Sync all the IPSets with any new information coming from the policy.
	i.synchronizePUACLs(contextID, policyrules.ApplicationACLs(), policyrules.NetworkACLs())

	return nil
}

func (i *iptables) CleanUp() error {
	if err := i.cleanACLs(); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	if err := i.ipset.DestroyAll(i.impl.GetIPSetPrefix()); err != nil {
		zap.L().Error("Failed to clean up ipsets", zap.Error(err))
	}

	return nil
}

func (i *iptables) updateAllTargetNetworks(cfg, oldConfig *runtime.Configuration) error {

	if err := i.updateTargetNetworks(i.targetTCPSet, oldConfig.TCPTargetNetworks, cfg.TCPTargetNetworks); err != nil {
		return err
	}

	if err := i.updateTargetNetworks(i.targetUDPSet, oldConfig.UDPTargetNetworks, cfg.UDPTargetNetworks); err != nil {
		return err
	}

	if err := i.updateTargetNetworks(i.excludedNetworksSet, oldConfig.ExcludedNetworks, cfg.ExcludedNetworks); err != nil {
		return err
	}

	return nil
}

// ACLProvider returns the current ACL provider that can be re-used by other entities.
func (i *Instance) ACLProvider() []provider.IptablesProvider {
	return []provider.IptablesProvider{i.iptv4.impl, i.iptv6.impl}
}

// InitializeChains initializes the chains.
func (i *iptables) initializeChains() error {

	cfg, err := i.newACLInfo(0, "", nil, 0)
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
		if err := i.impl.NewChain(rule[1], rule[3]); err != nil {
			return err
		}
	}

	return nil
}

// configureContainerRules adds the chain rules for a container.
// We separate in different methods to keep track of the changes
// independently.
func (i *iptables) configureContainerRules(cfg *ACLInfo) error {
	return i.addChainRules(cfg)
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *iptables) configureLinuxRules(cfg *ACLInfo) error {

	// These checks are for rather unusal error scenarios. We should
	// never see errors here. But better safe than sorry.
	if cfg.CgroupMark == "" {
		return errors.New("no mark value found")
	}

	if cfg.TCPPortSet == "" {
		return fmt.Errorf("port set was not found for the contextID. This should not happen")
	}

	return i.addChainRules(cfg)
}

func (i *iptables) deleteProxySets(proxyPortSetName string) error { // nolint
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

func createGlobalSets(ipsetPrefix string, ips provider.IpsetProvider, params *ipset.Params) (provider.Ipset, provider.Ipset, provider.Ipset, error) {

	var err error

	defer func() {
		if err != nil {
			ips.DestroyAll(ipsetPrefix) // nolint errcheck
		}
	}()

	targetTCPSet := ipsetPrefix + targetTCPNetworkSet
	targetUDPSet := ipsetPrefix + targetUDPNetworkSet
	excludedSet := ipsetPrefix + excludedNetworkSet

	targetSetNames := []string{targetTCPSet, targetUDPSet, excludedSet}

	targetSets := map[string]provider.Ipset{}

	existingSets, err := ips.ListIPSets()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to read current sets: %s", err)
	}

	setIndex := map[string]struct{}{}
	for _, s := range existingSets {
		setIndex[s] = struct{}{}
	}

	for _, t := range targetSetNames {
		_, ok := setIndex[t]
		createdSet, err := ips.NewIpset(t, "hash:net", params)
		if err != nil {
			if !ok {
				return nil, nil, nil, err
			}
			createdSet = ips.GetIpset(t)
		}
		if err = createdSet.Flush(); err != nil {
			return nil, nil, nil, err
		}
		targetSets[t] = createdSet
	}

	return targetSets[targetTCPSet], targetSets[targetUDPSet], targetSets[excludedSet], nil
}

type ipsetInfo struct {
	ipset      string
	ips        map[string]bool
	contextIDs map[string]bool
}

type aclIPset struct {
	ipset      string
	ports      []string
	protocols  []string
	extensions []string
	policy     *policy.FlowPolicy
}

func addToIPset(set provider.Ipset, data string) error {

	// ipset can not program this rule
	if data == "0.0.0.0/0" {
		if err := addToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := addToIPset(set, "128.0.0.0/1"); err != nil {
			return err
		}

		return nil
	}

	// ipset can not program this rule
	if data == "::/0" {
		if err := addToIPset(set, "::/1"); err != nil {
			return err
		}

		if err := addToIPset(set, "8000::/1"); err != nil {
			return err
		}

		return nil
	}

	return set.Add(data, 0)
}

func delFromIPset(set provider.Ipset, data string) error {

	if data == "0.0.0.0/0" {
		if err := delFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		if err := delFromIPset(set, "128.0.0.0/1"); err != nil {
			return err
		}
	}

	if data == "::/0" {
		if err := delFromIPset(set, "::/1"); err != nil {
			return err
		}

		if err := delFromIPset(set, "8000::/1"); err != nil {
			return err
		}
	}

	return set.Del(data)
}

func (i *iptables) removePUFromExternalNetworks(contextID string, serviceID string) {

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

func (i *iptables) destroyACLIPsets(contextID string) {
	for serviceID, info := range i.serviceIDToIPsets {
		if info.contextIDs[contextID] {
			i.removePUFromExternalNetworks(contextID, serviceID)
		}
	}
}

func (i *iptables) synchronizePUACLs(contextID string, appACLs, netACLs policy.IPRuleList) {
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

func (i *iptables) createACLIPSets(contextID string, rules policy.IPRuleList) ([]aclIPset, error) {
	var info *ipsetInfo

	ipFilter := i.impl.IPFilter()
	ipsetPrefix := i.impl.GetIPSetPrefix()
	ipsetParams := i.impl.GetIPSetParam()

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

			ipsetName := puPortSetName(contextID, ipsetPrefix+"ext-"+hashServiceID(rule.Policy.ServiceID))
			set, err := i.ipset.NewIpset(ipsetName, "hash:net", ipsetParams)
			if err != nil {
				return nil, err
			}

			for _, address := range rule.Addresses {
				netIP := net.ParseIP(address)
				if netIP == nil {
					netIP, _, _ = net.ParseCIDR(address)
				}

				if !ipFilter(netIP) {
					continue
				}

				if err := addToIPset(set, address); err != nil {
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

				netIP := net.ParseIP(address)
				if netIP == nil {
					netIP, _, _ = net.ParseCIDR(address)
				}

				if !ipFilter(netIP) {
					continue
				}

				// add new entries
				if !info.ips[address] {
					if err := addToIPset(i.ipset.GetIpset(info.ipset), address); err != nil {
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
					if err := delFromIPset(i.ipset.GetIpset(info.ipset), address); err != nil {
						return nil, err
					}
				}
			}

			info.ips = newips
			info.contextIDs[contextID] = true
		}

		acls = append(acls, aclIPset{
			ipset:      info.ipset,
			ports:      rule.Ports,
			protocols:  rule.Protocols,
			extensions: rule.Extensions,
			policy:     rule.Policy,
		})
	}

	return acls, nil
}

// Install rules will install all the rules and update the port sets.
func (i *iptables) installRules(cfg *ACLInfo, containerInfo *policy.PUInfo) error {
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

	if err := i.addExternalACLs(cfg.ContextID, cfg.AppChain, cfg.NetChain, appACLIPset, true); err != nil {
		return err
	}

	if err := i.addExternalACLs(cfg.ContextID, cfg.NetChain, cfg.AppChain, netACLIPset, false); err != nil {
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

// flushUDPConntrack will flush the UDP conntrack table that matches our networks.
func flushUDPConntrack(networks []string) {
	// TODD: Add proper UDP connection flash for Linux processes
	// make sure that we only flush for the initiating process.
	// cmd := "conntrack"
	// for _, n := range networks {
	// 	if _, err := exec.Command(cmd, "-D", "-p", "udp", "--src", n).Output(); err != nil && err.Error() != "exit status 1" {
	// 		zap.L().Warn("Failed to remove source conntrack entries for UDP target network", zap.Error(err))
	// 	}
	// 	if _, err := exec.Command(cmd, "-D", "-p", "udp", "--dst", n).Output(); err != nil && err.Error() != "exit status 1" {
	// 		zap.L().Warn("Failed to remove destination conntrack entries for UDP target network", zap.Error(err))
	// 	}
	// }
}

// SetTargetNetworks updates ths target networks. There are three different
// types of target networks:
//   - TCPTargetNetworks for TCP traffic (by default 0.0.0.0/0)
//   - UDPTargetNetworks for UDP traffic (by default empty)
//   - ExcludedNetworks that are always ignored (by default empty)

func (i *Instance) SetTargetNetworks(c *runtime.Configuration) error {

	if err := i.iptv4.SetTargetNetworks(c); err != nil {
		return err
	}

	if err := i.iptv6.SetTargetNetworks(c); err != nil {
		return err
	}

	return nil
}

// Run starts the iptables controller
func (i *Instance) Run(ctx context.Context) error {

	if err := i.iptv4.Run(ctx); err != nil {
		return err
	}

	if err := i.iptv6.Run(ctx); err != nil {
		return err
	}

	return nil
}

func (i *Instance) ConfigureRules(version int, contextID string, pu *policy.PUInfo) error {
	if err := i.iptv4.ConfigureRules(version, contextID, pu); err != nil {
		return err
	}

	if err := i.iptv6.ConfigureRules(version, contextID, pu); err != nil {
		return err
	}

	return nil
}

// DeleteRules implements the DeleteRules interface. This is responsible
// for cleaning all ACLs and associated chains, as well as ll the sets
// that we have created. Note, that this only clears up the state
// for a given processing unit.
func (i *Instance) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, puType common.PUType) error {

	if err := i.iptv4.DeleteRules(version, contextID, tcpPorts, udpPorts, mark, username, proxyPort, puType); err != nil {
		zap.L().Warn("Delete rules for iptables v4 returned error")
	}

	if err := i.iptv6.DeleteRules(version, contextID, tcpPorts, udpPorts, mark, username, proxyPort, puType); err != nil {
		zap.L().Warn("Delete rules for iptables v6 returned error")
	}

	return nil
}

// UpdateRules implements the update part of the interface. Update will call
// installrules to install the new rules and then it will delete the old rules.
// For installations that do not have latests iptables-restore we time
// the operations so that the switch is almost atomic, by creating the new rules
// first. For latest kernel versions iptables-restorce will update all the rules
// in one shot.
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {

	if err := i.iptv4.UpdateRules(version, contextID, containerInfo, oldContainerInfo); err != nil {
		return err
	}

	if err := i.iptv6.UpdateRules(version, contextID, containerInfo, oldContainerInfo); err != nil {
		return err
	}

	return nil
}

// CleanUp requires the implementor to clean up all ACLs and destroy all
// the IP sets.
func (i *Instance) CleanUp() error {

	if err := i.iptv4.CleanUp(); err != nil {
		return err
	}

	if err := i.iptv6.CleanUp(); err != nil {
		return err
	}

	return nil
}
